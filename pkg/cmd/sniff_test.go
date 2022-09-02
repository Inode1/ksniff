package cmd

import (
	"fmt"
	"ksniff/pkg/config"
	"strings"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"testing"
)

type completer interface {
	Complete(cmd *cobra.Command, args []string) error
}

func TestComplete_NotEnoughArguments(t *testing.T) {
	type testCase struct {
		name   string
		ksniff completer
	}
	tests := []testCase{
		{"pod", NewKsniffPod(config.NewKsniffSettings(genericclioptions.IOStreams{}))},
		{"node", NewKsniffNode(config.NewKsniffSettings(genericclioptions.IOStreams{}))},
	}
	// given
	cmd := &cobra.Command{}
	var commands []string

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// when
			err := test.ksniff.Complete(cmd, commands)

			// then
			assert.NotNil(t, err)
			assert.True(t, strings.Contains(err.Error(), "not enough arguments"))
		})
	}
}

func TestComplete_EmptyName(t *testing.T) {
	type testCase struct {
		name   string
		ksniff completer
	}
	tests := []testCase{
		{"pod", NewKsniffPod(config.NewKsniffSettings(genericclioptions.IOStreams{}))},
		{"node", NewKsniffNode(config.NewKsniffSettings(genericclioptions.IOStreams{}))},
	}
	// given
	cmd := &cobra.Command{}
	commands := []string{""}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// when
			err := test.ksniff.Complete(cmd, commands)

			// then
			assert.NotNil(t, err)
			assert.True(t, strings.Contains(err.Error(), fmt.Sprintf("%s name is empty", test.name)))
		})
	}
}

func TestComplete_PodNameSpecified(t *testing.T) {
	// given
	settings := config.NewKsniffSettings(genericclioptions.IOStreams{})
	sniff := NewKsniffPod(settings)
	cmd := NewCmdSniff(genericclioptions.IOStreams{})
	var commands []string

	// when
	err := sniff.Complete(cmd, append(commands, "pod-name"))

	// then
	assert.Nil(t, err)
	assert.Equal(t, "pod-name", settings.UserSpecifiedPodName)
}

func TestComplete_NodeNameSpecified(t *testing.T) {
	// given
	settings := config.NewKsniffSettings(genericclioptions.IOStreams{})
	sniff := NewKsniffNode(settings)
	cmd := NewCmdSniff(genericclioptions.IOStreams{})
	var commands []string

	// when
	err := sniff.Complete(cmd, append(commands, "node-name"))

	// then
	assert.Nil(t, err)
	assert.Equal(t, "node-name", settings.DetectedPodNodeName)
}
