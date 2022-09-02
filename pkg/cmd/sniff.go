package cmd

import (
	"fmt"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

const (
	cpuLimit = "250m"
	memLimit = "256Mi"
)

var tcpdumpLocalBinaryPathLookupList []string

type Ksniff struct {
	configFlags      *genericclioptions.ConfigFlags
	resultingContext *api.Context
	clientset        *kubernetes.Clientset
	restConfig       *rest.Config
	rawConfig        api.Config
	settings         *config.KsniffSettings
	snifferService   sniffer.SnifferService
	wireshark        *exec.Cmd
}

func NewCmdSniff(streams genericclioptions.IOStreams) *cobra.Command {
	ksniffSettings := config.NewKsniffSettings(streams)

	rootCmd := &cobra.Command{
		Use:          "sniff",
		Short:        "Perform network sniffing on a container or node running in a kubernetes cluster.",
		SilenceUsage: true,
	}

	podCmd := NewCmdSniffPod(ksniffSettings)
	nodeCmd := NewCmdSniffNode(ksniffSettings)

	rootCmd.AddCommand(podCmd)
	rootCmd.AddCommand(nodeCmd)

	rootCmd.PersistentFlags().StringVarP(&ksniffSettings.UserSpecifiedNamespace, "namespace", "n", "", "namespace (optional)")
	_ = viper.BindEnv("namespace", "KUBECTL_PLUGINS_CURRENT_NAMESPACE")
	_ = viper.BindPFlag("namespace", rootCmd.PersistentFlags().Lookup("namespace"))

	rootCmd.PersistentFlags().StringVarP(&ksniffSettings.UserSpecifiedInterface, "interface", "i", "any", "pod interface to packet capture (optional)")
	_ = viper.BindEnv("interface", "KUBECTL_PLUGINS_LOCAL_FLAG_INTERFACE")
	_ = viper.BindPFlag("interface", rootCmd.PersistentFlags().Lookup("interface"))

	rootCmd.PersistentFlags().StringVarP(&ksniffSettings.UserSpecifiedFilter, "filter", "f", "", "tcpdump filter (optional)")
	_ = viper.BindEnv("filter", "KUBECTL_PLUGINS_LOCAL_FLAG_FILTER")
	_ = viper.BindPFlag("filter", rootCmd.PersistentFlags().Lookup("filter"))

	rootCmd.PersistentFlags().StringVarP(&ksniffSettings.UserSpecifiedOutputFile, "output-file", "o", "",
		"output file path, tcpdump output will be redirect to this file instead of wireshark (optional) ('-' stdout)")
	_ = viper.BindEnv("output-file", "KUBECTL_PLUGINS_LOCAL_FLAG_OUTPUT_FILE")
	_ = viper.BindPFlag("output-file", rootCmd.PersistentFlags().Lookup("output-file"))

	rootCmd.PersistentFlags().BoolVarP(&ksniffSettings.UserSpecifiedVerboseMode, "verbose", "v", false,
		"if specified, ksniff output will include debug information (optional)")
	_ = viper.BindEnv("verbose", "KUBECTL_PLUGINS_LOCAL_FLAG_VERBOSE")
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))

	rootCmd.PersistentFlags().DurationVarP(&ksniffSettings.UserSpecifiedPodCreateTimeout, "pod-creation-timeout", "",
		1*time.Minute, "the length of time to wait for privileged pod to be created (e.g. 20s, 2m, 1h). "+
			"A value of zero means the creation never times out.")

	rootCmd.PersistentFlags().StringVarP(&ksniffSettings.TCPDumpImage, "tcpdump-image", "", "",
		"the tcpdump container image (optional)")
	_ = viper.BindEnv("tcpdump-image", "KUBECTL_PLUGINS_LOCAL_FLAG_TCPDUMP_IMAGE")
	_ = viper.BindPFlag("tcpdump-image", rootCmd.PersistentFlags().Lookup("tcpdump-image"))

	rootCmd.PersistentFlags().StringVarP(&ksniffSettings.UserSpecifiedKubeContext, "context", "x", "",
		"kubectl context to work on (optional)")
	_ = viper.BindEnv("context", "KUBECTL_PLUGINS_CURRENT_CONTEXT")
	_ = viper.BindPFlag("context", rootCmd.PersistentFlags().Lookup("context"))

	rootCmd.PersistentFlags().StringVar(&ksniffSettings.UserSpecifiedCPU, "cpu", cpuLimit, "cpu limit for tcpdump pod (optional)")
	_ = viper.BindEnv("cpu", "KUBECTL_PLUGINS_LOCAL_FLAG_CPU")
	_ = viper.BindPFlag("cpu", rootCmd.PersistentFlags().Lookup("cpu"))

	rootCmd.PersistentFlags().StringVar(&ksniffSettings.UserSpecifiedMemory, "memory", memLimit, "memory limit for tcpdump pod (optional)")
	_ = viper.BindEnv("memory", "KUBECTL_PLUGINS_LOCAL_FLAG_MEMORY")
	_ = viper.BindPFlag("memory", rootCmd.PersistentFlags().Lookup("memory"))

	return rootCmd
}

func (o *Ksniff) Complete(cmd *cobra.Command, args []string) error {

	o.settings.UserSpecifiedNamespace = viper.GetString("namespace")
	o.settings.UserSpecifiedContainer = viper.GetString("container")
	o.settings.UserSpecifiedInterface = viper.GetString("interface")
	o.settings.UserSpecifiedFilter = viper.GetString("filter")
	o.settings.UserSpecifiedOutputFile = viper.GetString("output-file")
	o.settings.UserSpecifiedLocalTcpdumpPath = viper.GetString("local-tcpdump-path")
	o.settings.UserSpecifiedRemoteTcpdumpPath = viper.GetString("remote-tcpdump-path")
	o.settings.UserSpecifiedVerboseMode = viper.GetBool("verbose")
	o.settings.UserSpecifiedPrivilegedMode = viper.GetBool("privileged")
	o.settings.UserSpecifiedKubeContext = viper.GetString("context")
	o.settings.UserSpecifiedCPU = viper.GetString("cpu")
	o.settings.UserSpecifiedMemory = viper.GetString("memory")
	o.settings.Image = viper.GetString("image")
	o.settings.TCPDumpImage = viper.GetString("tcpdump-image")
	o.settings.SocketPath = viper.GetString("socket")
	o.settings.UseDefaultImage = !viper.IsSet("image")
	o.settings.UseDefaultTCPDumpImage = !viper.IsSet("tcpdump-image")
	o.settings.UseDefaultSocketPath = !viper.IsSet("socket")
	o.settings.UserSpecifiedServiceAccount = viper.GetString("serviceaccount")

	var err error

	if o.settings.UserSpecifiedVerboseMode {
		log.Info("running in verbose mode")
		log.SetLevel(log.DebugLevel)
	}

	tcpdumpLocalBinaryPathLookupList, err = o.buildTcpdumpBinaryPathLookupList()
	if err != nil {
		return err
	}

	o.rawConfig, err = o.configFlags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return err
	}

	var currentContext *api.Context
	var exists bool

	if o.settings.UserSpecifiedKubeContext != "" {
		currentContext, exists = o.rawConfig.Contexts[o.settings.UserSpecifiedKubeContext]
	} else {
		currentContext, exists = o.rawConfig.Contexts[o.rawConfig.CurrentContext]
	}

	if !exists {
		return errors.New("context doesn't exist")
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{
		CurrentContext: o.settings.UserSpecifiedKubeContext,
	}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	o.restConfig, err = kubeConfig.ClientConfig()
	if err != nil {
		return err
	}

	o.restConfig.Timeout = 30 * time.Second

	o.clientset, err = kubernetes.NewForConfig(o.restConfig)
	if err != nil {
		return err
	}

	o.resultingContext = currentContext.DeepCopy()
	if o.settings.UserSpecifiedNamespace != "" {
		o.resultingContext.Namespace = o.settings.UserSpecifiedNamespace
	}

	return nil
}

func (o *Ksniff) buildTcpdumpBinaryPathLookupList() ([]string, error) {
	userHomeDir, err := homedir.Dir()
	if err != nil {
		return nil, err
	}

	ksniffBinaryPath, err := filepath.EvalSymlinks(os.Args[0])
	if err != nil {
		return nil, err
	}

	ksniffBinaryDir := filepath.Dir(ksniffBinaryPath)
	ksniffBinaryPath = filepath.Join(ksniffBinaryDir, tcpdumpBinaryName)

	kubeKsniffPluginFolder := filepath.Join(userHomeDir, filepath.FromSlash("/.kube/plugin/sniff/"), tcpdumpBinaryName)

	return append([]string{o.settings.UserSpecifiedLocalTcpdumpPath, ksniffBinaryPath},
		filepath.Join("/usr/local/bin/", tcpdumpBinaryName), kubeKsniffPluginFolder), nil
}

func (o *Ksniff) cleanupSniffer() {
	log.Info("starting sniffer cleanup")
	err := o.snifferService.Cleanup()
	if err != nil {
		log.WithError(err).Error("failed to teardown sniffer, a manual teardown is required.")
	}
	log.Info("sniffer cleanup completed successfully")
}

func (o *Ksniff) setupSignalHandler() chan interface{} {
	signals := make(chan os.Signal, 1)
	exit := make(chan interface{})

	signal.Notify(signals, syscall.SIGINT)
	go func() {
		for {
			select {
			case sig := <-signals:
				if sig == syscall.SIGINT || sig == syscall.SIGTERM {
					o.cleanupSniffer()

					// Kill wireshark if used
					if o.wireshark != nil {
						if o.wireshark.Process != nil {
							err := o.wireshark.Process.Kill()
							if err != nil && err != os.ErrProcessDone {
								log.WithError(err).Error("failed to kill wireshark process")
							} else {
								log.Debug("wireshark process killed")
							}
						}
					}

					close(signals)
				}
			case <-exit:
				return
			}

		}
	}()
	return exit
}

func (o *Ksniff) Run() error {
	log.Infof("sniffing on pod: '%s' [namespace: '%s', container: '%s', filter: '%s', interface: '%s']",
		o.settings.UserSpecifiedPodName, o.resultingContext.Namespace, o.settings.UserSpecifiedContainer, o.settings.UserSpecifiedFilter, o.settings.UserSpecifiedInterface)

	err := o.snifferService.Setup()
	if err != nil {
		return err
	}

	// Ensure sniffer is clean on interrupt
	closeHandler := o.setupSignalHandler()

	// Ensure sniffer is clean on complete
	defer func() {
		closeHandler <- true
	}()

	if o.settings.UserSpecifiedOutputFile != "" {
		log.Infof("output file option specified, storing output in: '%s'", o.settings.UserSpecifiedOutputFile)

		var err error
		var fileWriter io.Writer

		if o.settings.UserSpecifiedOutputFile == "-" {
			fileWriter = os.Stdout
		} else {
			fileWriter, err = os.Create(o.settings.UserSpecifiedOutputFile)
			if err != nil {
				return err
			}
		}

		err = o.snifferService.Start(fileWriter)
		if err != nil {
			return err
		}

	} else {
		log.Info("spawning wireshark!")

		title := fmt.Sprintf("gui.window_title:%s/%s/%s", o.resultingContext.Namespace, o.settings.UserSpecifiedPodName, o.settings.UserSpecifiedContainer)
		o.wireshark = exec.Command("wireshark", "-k", "-i", "-", "-o", title)

		stdinWriter, err := o.wireshark.StdinPipe()
		if err != nil {
			return err
		}

		go func() {
			err := o.snifferService.Start(stdinWriter)
			if err != nil {
				log.WithError(err).Errorf("failed to start remote sniffing, stopping wireshark")
				_ = o.wireshark.Process.Kill()
			}
		}()

		err = o.wireshark.Run()
		o.cleanupSniffer()
		return err
	}

	return nil
}

func (o *Ksniff) completeConfig() error {
	var err error

	if o.settings.UserSpecifiedVerboseMode {
		log.Info("running in verbose mode")
		log.SetLevel(log.DebugLevel)
	}

	o.rawConfig, err = o.configFlags.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return err
	}

	var currentContext *api.Context
	var exists bool

	if o.settings.UserSpecifiedKubeContext != "" {
		currentContext, exists = o.rawConfig.Contexts[o.settings.UserSpecifiedKubeContext]
	} else {
		currentContext, exists = o.rawConfig.Contexts[o.rawConfig.CurrentContext]
	}

	if !exists {
		return errors.New("context doesn't exist")
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	configOverrides := &clientcmd.ConfigOverrides{
		CurrentContext: o.settings.UserSpecifiedKubeContext,
	}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	o.restConfig, err = kubeConfig.ClientConfig()
	if err != nil {
		return err
	}

	o.restConfig.Timeout = 30 * time.Second

	o.clientset, err = kubernetes.NewForConfig(o.restConfig)
	if err != nil {
		return err
	}

	o.resultingContext = currentContext.DeepCopy()
	if o.settings.UserSpecifiedNamespace != "" {
		o.resultingContext.Namespace = o.settings.UserSpecifiedNamespace
	}

	return nil
}
