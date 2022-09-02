package cmd

import (
	"context"
	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer"
	"ksniff/pkg/service/sniffer/runtime"
	"os"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

var (
	ksniffPodExample = "kubectl sniff pod hello-minikube-7c77b68cff-qbvsd -c hello-minikube"
)

const tcpdumpBinaryName = "static-tcpdump"
const tcpdumpRemotePath = "/tmp/static-tcpdump"

type KsniffPod struct {
	Ksniff
}

func NewKsniffPod(settings *config.KsniffSettings) *KsniffPod {
	return &KsniffPod{Ksniff{settings: settings, configFlags: genericclioptions.NewConfigFlags(true)}}
}

func NewCmdSniffPod(ksniffSettings *config.KsniffSettings) *cobra.Command {
	ksniff := NewKsniffPod(ksniffSettings)

	cmd := &cobra.Command{
		Use:          "pod pod-name [-n namespace] [-c container] [-f filter] [-o output-file] [-l local-tcpdump-path] [-r remote-tcpdump-path]",
		Short:        "Perform network sniffing on a container running in a kubernetes cluster.",
		Example:      ksniffPodExample,
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := ksniff.Complete(c, args); err != nil {
				return err
			}
			if err := ksniff.Validate(); err != nil {
				return err
			}
			if err := ksniff.Run(); err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedContainer, "container", "c", "", "container (optional)")
	_ = viper.BindEnv("container", "KUBECTL_PLUGINS_LOCAL_FLAG_CONTAINER")
	_ = viper.BindPFlag("container", cmd.Flags().Lookup("container"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedLocalTcpdumpPath, "local-tcpdump-path", "l", "",
		"local static tcpdump binary path (optional)")
	_ = viper.BindEnv("local-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_LOCAL_TCPDUMP_PATH")
	_ = viper.BindPFlag("local-tcpdump-path", cmd.Flags().Lookup("local-tcpdump-path"))

	cmd.Flags().BoolVarP(&ksniffSettings.UserSpecifiedPrivilegedMode, "privileged", "p", false,
		"if specified, ksniff will deploy another pod that have privileges to attach target pod network namespace")
	_ = viper.BindEnv("privileged", "KUBECTL_PLUGINS_LOCAL_FLAG_PRIVILEGED")
	_ = viper.BindPFlag("privileged", cmd.Flags().Lookup("privileged"))

	cmd.Flags().StringVarP(&ksniffSettings.Image, "image", "", "",
		"the privileged container image (optional)")
	_ = viper.BindEnv("image", "KUBECTL_PLUGINS_LOCAL_FLAG_IMAGE")
	_ = viper.BindPFlag("image", cmd.Flags().Lookup("image"))

	cmd.Flags().StringVarP(&ksniffSettings.SocketPath, "socket", "", "",
		"the container runtime socket path (optional)")
	_ = viper.BindEnv("socket", "KUBECTL_PLUGINS_SOCKET_PATH")
	_ = viper.BindPFlag("socket", cmd.Flags().Lookup("socket"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedServiceAccount, "serviceaccount", "s", "",
		"the privileged container service account (optional)")
	_ = viper.BindEnv("serviceaccount", "KUBECTL_PLUGINS_LOCAL_FLAG_SERVICE_ACCOUNT")
	_ = viper.BindPFlag("serviceaccount", cmd.Flags().Lookup("serviceaccount"))

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedRemoteTcpdumpPath, "remote-tcpdump-path", "r", tcpdumpRemotePath,
		"remote static tcpdump binary path (optional)")
	_ = viper.BindEnv("remote-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_REMOTE_TCPDUMP_PATH")
	_ = viper.BindPFlag("remote-tcpdump-path", cmd.Flags().Lookup("remote-tcpdump-path"))

	return cmd
}

func (o *KsniffPod) Complete(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		_ = cmd.Usage()
		return errors.New("not enough arguments")
	}

	o.settings.UserSpecifiedPodName = args[0]
	if o.settings.UserSpecifiedPodName == "" {
		return errors.New("pod name is empty")
	}

	return o.Ksniff.Complete(cmd, args)
}

func findLocalTcpdumpBinaryPath() (string, error) {
	log.Debugf("searching for tcpdump binary using lookup list: '%v'", tcpdumpLocalBinaryPathLookupList)

	for _, possibleTcpdumpPath := range tcpdumpLocalBinaryPathLookupList {
		if _, err := os.Stat(possibleTcpdumpPath); err == nil {
			log.Debugf("tcpdump binary found at: '%s'", possibleTcpdumpPath)

			return possibleTcpdumpPath, nil
		}

		log.Debugf("tcpdump binary was not found at: '%s'", possibleTcpdumpPath)
	}

	return "", errors.Errorf("couldn't find static tcpdump binary on any of: '%v'", tcpdumpLocalBinaryPathLookupList)
}

func (o *KsniffPod) Validate() error {
	if len(o.rawConfig.CurrentContext) == 0 {
		return errors.New("context doesn't exist")
	}

	if o.resultingContext.Namespace == "" {
		return errors.New("namespace value is empty should be custom or default")
	}

	var err error

	if !o.settings.UserSpecifiedPrivilegedMode {
		o.settings.UserSpecifiedLocalTcpdumpPath, err = findLocalTcpdumpBinaryPath()
		if err != nil {
			return err
		}

		log.Infof("using tcpdump path at: '%s'", o.settings.UserSpecifiedLocalTcpdumpPath)
	} else if o.settings.UserSpecifiedServiceAccount != "" {
		_, err := o.clientset.CoreV1().ServiceAccounts(o.resultingContext.Namespace).Get(context.TODO(), o.settings.UserSpecifiedServiceAccount, v1.GetOptions{})
		if err != nil {
			return err
		}
	}

	pod, err := o.clientset.CoreV1().Pods(o.resultingContext.Namespace).Get(context.TODO(), o.settings.UserSpecifiedPodName, v1.GetOptions{})
	if err != nil {
		return err
	}

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return errors.Errorf("cannot sniff on a container in a completed pod; current phase is %s", pod.Status.Phase)
	}

	o.settings.DetectedPodNodeName = pod.Spec.NodeName

	log.Debugf("pod '%s' status: '%s'", o.settings.UserSpecifiedPodName, pod.Status.Phase)

	if len(pod.Spec.Containers) < 1 {
		return errors.New("no containers in specified pod")
	}

	if o.settings.UserSpecifiedContainer == "" {
		log.Info("no container specified, taking first container we found in pod.")
		o.settings.UserSpecifiedContainer = pod.Spec.Containers[0].Name
		log.Infof("selected container: '%s'", o.settings.UserSpecifiedContainer)
	}

	if err := o.findContainerId(pod); err != nil {
		return err
	}

	kubernetesApiService := kube.NewKubernetesApiService(o.clientset, o.restConfig, o.resultingContext.Namespace)

	if o.settings.UserSpecifiedPrivilegedMode {
		log.Info("sniffing method: privileged pod")
		bridge := runtime.NewContainerRuntimeBridge(o.settings.DetectedContainerRuntime)
		o.snifferService = sniffer.NewPrivilegedPodRemoteSniffingService(o.settings, kubernetesApiService, bridge)
	} else {
		log.Info("sniffing method: upload static tcpdump")
		o.snifferService = sniffer.NewUploadTcpdumpRemoteSniffingService(o.settings, kubernetesApiService)
	}

	return nil
}

func (o *KsniffPod) findContainerId(pod *corev1.Pod) error {
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if o.settings.UserSpecifiedContainer == containerStatus.Name {
			result := strings.Split(containerStatus.ContainerID, "://")
			if len(result) != 2 {
				break
			}
			o.settings.DetectedContainerRuntime = result[0]
			o.settings.DetectedContainerId = result[1]
			return nil
		}
	}

	return errors.Errorf("couldn't find container: '%s' in pod: '%s'", o.settings.UserSpecifiedContainer, o.settings.UserSpecifiedPodName)
}
