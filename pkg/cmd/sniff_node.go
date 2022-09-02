package cmd

import (
	"context"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	_ "k8s.io/client-go/plugin/pkg/client/auth/azure"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
	"ksniff/kube"
	"ksniff/pkg/config"
	"ksniff/pkg/service/sniffer"
)

var (
	ksniffNodeExample = "kubectl sniff node node-1"
)

type KsniffNode struct {
	Ksniff
}

func NewKsniffNode(settings *config.KsniffSettings) *KsniffNode {
	return &KsniffNode{Ksniff{settings: settings, configFlags: genericclioptions.NewConfigFlags(true)}}
}

func NewCmdSniffNode(ksniffSettings *config.KsniffSettings) *cobra.Command {
	ksniff := NewKsniffNode(ksniffSettings)

	cmd := &cobra.Command{
		Use:          "node node-name [-f filter] [-o output-file]",
		Short:        "Perform network sniffing on a node in a kubernetes cluster.",
		Example:      ksniffNodeExample,
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

	cmd.Flags().StringVarP(&ksniffSettings.UserSpecifiedRemoteTcpdumpPath, "remote-tcpdump-path", "r", "tcpdump",
		"remote static tcpdump binary path (optional)")
	_ = viper.BindEnv("remote-tcpdump-path", "KUBECTL_PLUGINS_LOCAL_FLAG_REMOTE_TCPDUMP_PATH")
	_ = viper.BindPFlag("remote-tcpdump-path", cmd.Flags().Lookup("remote-tcpdump-path"))

	return cmd
}

func (o *KsniffNode) Complete(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		_ = cmd.Usage()
		return errors.New("not enough arguments")
	}

	o.settings.DetectedPodNodeName = args[0]
	if o.settings.DetectedPodNodeName == "" {
		return errors.New("node name is empty")
	}

	return o.Ksniff.Complete(cmd, args)
}

func (o *KsniffNode) Validate() error {
	if len(o.rawConfig.CurrentContext) == 0 {
		return errors.New("context doesn't exist")
	}

	var err error

	node, err := o.clientset.CoreV1().Nodes().Get(context.TODO(), o.settings.DetectedPodNodeName, v1.GetOptions{})
	if err != nil {
		return err
	}

	log.Debugf("node '%s' status: '%s'", o.settings.DetectedPodNodeName, node.Status.Phase)

	kubernetesApiService := kube.NewKubernetesApiService(o.clientset, o.restConfig, o.resultingContext.Namespace)

	o.snifferService = sniffer.NewNodeSniffingService(o.settings, kubernetesApiService)

	return nil
}
