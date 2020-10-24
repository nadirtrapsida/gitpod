// Copyright (c) 2020 TypeFox GmbH. All rights reserved.
// Licensed under the GNU Affero General Public License (AGPL).
// See License-AGPL.txt in the project root for license information.

package ports

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/gitpod-io/gitpod/supervisor/pkg/gitpod"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// RangeConfig is a port range config
type RangeConfig struct {
	*gitpod.PortsItems
	Start uint32
	End   uint32
}

// Configs provides access to port configurations
type Configs struct {
	workspaceConfigs     map[uint32]*gitpod.PortConfig
	instancePortConfigs  map[uint32]*gitpod.PortConfig
	instanceRangeConfigs []*RangeConfig
}

// ForEach iterates over all configured ports
func (configs *Configs) ForEach(callback func(port uint32, config *gitpod.PortConfig)) {
	if configs == nil {
		return
	}
	visited := make(map[uint32]struct{})
	for _, configs := range []map[uint32]*gitpod.PortConfig{configs.instancePortConfigs, configs.workspaceConfigs} {
		for port, config := range configs {
			_, exists := visited[port]
			if exists {
				continue
			}
			visited[port] = struct{}{}
			callback(port, config)
		}
	}
}

// Get returns the config for the give port
func (configs *Configs) Get(port uint32) (*gitpod.PortConfig, bool) {
	if configs == nil {
		return nil, false
	}
	config, exists := configs.instancePortConfigs[port]
	if exists {
		return config, true
	}
	config, exists = configs.workspaceConfigs[port]
	if exists {
		return config, true
	}
	return nil, false
}

// GetFromRange returns the port config from the port range config
func (configs *Configs) GetFromRange(port uint32) (*gitpod.PortConfig, bool) {
	if configs == nil {
		return nil, false
	}
	for _, rangeConfig := range configs.instanceRangeConfigs {
		if rangeConfig.Start <= port && port <= rangeConfig.End {
			return &gitpod.PortConfig{
				Port:       float64(port),
				OnOpen:     rangeConfig.OnOpen,
				Visibility: rangeConfig.Visibility,
			}, true
		}
	}
	return nil, false
}

// ConfigInterace allows to watch port configurations
type ConfigInterace interface {
	// Observe provides channels triggered whenever the port configurations are changed.
	Observe(ctx context.Context) (<-chan *Configs, <-chan error)
}

// ConfigService allows to watch port configurations
type ConfigService struct {
	workspaceID   string
	configService gitpod.ConfigInterface
	gitpodAPI     gitpod.APIInterface
	parser        *configParser
}

// NewConfigService creates a new instance of ConfigService
func NewConfigService(workspaceID string, configService gitpod.ConfigInterface, gitpodAPI gitpod.APIInterface) *ConfigService {
	return &ConfigService{
		workspaceID:   workspaceID,
		configService: configService,
		gitpodAPI:     gitpodAPI,
		parser:        newConfigParser(),
	}
}

// Observe provides channels triggered whenever the port configurations are changed.
func (service *ConfigService) Observe(ctx context.Context) (<-chan *Configs, <-chan error) {
	updatesChan := make(chan *Configs)
	errorsChan := make(chan error, 1)

	go func() {
		defer close(updatesChan)
		defer close(errorsChan)

		configs, errs := service.configService.Observe(ctx)

		current := &Configs{}
		if service.gitpodAPI != nil {
			info, err := service.gitpodAPI.GetWorkspace(ctx, service.workspaceID)
			if err != nil {
				errorsChan <- err
			} else {
				current.workspaceConfigs = service.parser.parseWorkspaceConfigs(info.Workspace.Config.Ports)
				updatesChan <- &Configs{workspaceConfigs: current.workspaceConfigs}
			}
		} else {
			errorsChan <- errors.New("could not connect to Gitpod API to fetch workspace port configs")
		}

		for {
			select {
			case <-ctx.Done():
				return
			case err := <-errs:
				errorsChan <- err
			case config := <-configs:
				if service.update(config, current) {
					updatesChan <- &Configs{
						workspaceConfigs:     current.workspaceConfigs,
						instancePortConfigs:  current.instancePortConfigs,
						instanceRangeConfigs: current.instanceRangeConfigs,
					}
				}
			}
		}
	}()
	return updatesChan, errorsChan
}

func (service *ConfigService) update(config *gitpod.GitpodConfig, current *Configs) bool {
	currentPortConfigs, currentRangeConfigs := current.instancePortConfigs, current.instanceRangeConfigs
	var ports []*gitpod.PortsItems
	if config != nil {
		ports = config.Ports
	}
	portConfigs, rangeConfigs := service.parser.parseInstanceConfigs(ports)
	current.instancePortConfigs = portConfigs
	current.instanceRangeConfigs = rangeConfigs
	return !(cmp.Equal(currentPortConfigs, portConfigs, cmpopts.SortMaps(func(x, y uint32) bool { return x < y })) && cmp.Equal(currentRangeConfigs, rangeConfigs))
}

type configParser struct {
	portRangeRegexp *regexp.Regexp
}

func newConfigParser() *configParser {
	return &configParser{
		portRangeRegexp: regexp.MustCompile("^(\\d+)[-:](\\d+)$"),
	}
}

func (parser *configParser) parseWorkspaceConfigs(ports []*gitpod.PortConfig) (portConfigs map[uint32]*gitpod.PortConfig) {
	for _, config := range ports {
		if portConfigs == nil {
			portConfigs = make(map[uint32]*gitpod.PortConfig)
		}
		port := uint32(config.Port)
		_, exists := portConfigs[port]
		if !exists {
			portConfigs[port] = config
		}
	}
	return portConfigs
}

func (parser *configParser) parseInstanceConfigs(ports []*gitpod.PortsItems) (portConfigs map[uint32]*gitpod.PortConfig, rangeConfigs []*RangeConfig) {
	for _, config := range ports {
		rawPort := fmt.Sprintf("%v", config.Port)
		Port, err := strconv.Atoi(rawPort)
		if err == nil {
			if portConfigs == nil {
				portConfigs = make(map[uint32]*gitpod.PortConfig)
			}
			port := uint32(Port)
			_, exists := portConfigs[port]
			if !exists {
				portConfigs[port] = &gitpod.PortConfig{
					OnOpen:     config.OnOpen,
					Port:       float64(Port),
					Visibility: config.Visibility,
				}
			}
			continue
		}
		matches := parser.portRangeRegexp.FindStringSubmatch(rawPort)
		if len(matches) != 3 {
			continue
		}
		start, err := strconv.Atoi(matches[1])
		if err != nil {
			continue
		}
		end, err := strconv.Atoi(matches[2])
		if err != nil || start >= end {
			continue
		}
		rangeConfigs = append(rangeConfigs, &RangeConfig{
			PortsItems: config,
			Start:      uint32(start),
			End:        uint32(end),
		})
	}
	return portConfigs, rangeConfigs
}
