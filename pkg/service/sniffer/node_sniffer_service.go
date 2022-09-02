package sniffer

import (
	"io"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	"ksniff/kube"
	"ksniff/pkg/config"
)

type NodeSnifferService struct {
	settings             *config.KsniffSettings
	hostPod              *v1.Pod
	containerName        string
	targetProcessId      *string
	kubernetesApiService kube.KubernetesApiService
}

func NewNodeSniffingService(options *config.KsniffSettings, service kube.KubernetesApiService) SnifferService {
	return &NodeSnifferService{settings: options, containerName: "ksniff-host", kubernetesApiService: service}
}

func (p *NodeSnifferService) Setup() error {
	var err error

	log.Infof("creating privileged pod on node: '%s'", p.settings.DetectedPodNodeName)

	if p.settings.UseDefaultTCPDumpImage {
		p.settings.TCPDumpImage = "docker.io/maintained/tcpdump:latest"
	}

	p.hostPod, err = p.kubernetesApiService.CreateHostNetworkPod(
		p.settings.DetectedPodNodeName,
		p.containerName,
		p.settings.TCPDumpImage,
		p.settings.UserSpecifiedPodCreateTimeout,
		p.settings.UserSpecifiedCPU,
		p.settings.UserSpecifiedMemory,
	)
	if err != nil {
		log.WithError(err).Errorf("failed to create privileged pod on node: '%s'", p.settings.DetectedPodNodeName)
		return err
	}

	log.Infof("pod: '%s' created successfully on node: '%s'", p.hostPod.Name, p.settings.DetectedPodNodeName)

	return nil
}

func (p *NodeSnifferService) Cleanup() error {
	if p.hostPod == nil {
		return nil
	}
	log.Infof("removing pod: '%s'", p.hostPod.Name)

	err := p.kubernetesApiService.DeletePod(p.hostPod.Name)
	if err != nil {
		log.WithError(err).Errorf("failed to remove pod: '%s", p.hostPod.Name)
		return err
	}

	log.Infof("pod: '%s' removed successfully", p.hostPod.Name)

	return nil
}

func (p *NodeSnifferService) Start(stdOut io.Writer) error {
	return executeTcpDump(p.hostPod.Name, p.containerName, p.kubernetesApiService, p.settings, stdOut)
}
