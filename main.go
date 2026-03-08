/*
Copyright AppsCode Inc. and Contributors

Licensed under the AppsCode Community License 1.0.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://github.com/appscode/licenses/raw/1.0.0/AppsCode-Community-1.0.0.md

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	flag "github.com/spf13/pflag"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"
)

const resourceNameSep = "\x1f"

type ruleKey struct {
	apiGroup         string
	resource         string
	resourceNamesKey string
	nonResourceURL   string
}

type aggregator struct {
	rules map[ruleKey]sets.Set[string]
}

func newAggregator() *aggregator {
	return &aggregator{rules: map[ruleKey]sets.Set[string]{}}
}

func (a *aggregator) addRule(rule rbacv1.PolicyRule) {
	verbs := normalizeList(rule.Verbs)
	if len(verbs) == 0 {
		return
	}

	if len(rule.NonResourceURLs) > 0 {
		for _, url := range normalizeList(rule.NonResourceURLs) {
			key := ruleKey{nonResourceURL: url}
			a.insertVerbs(key, verbs)
		}
		return
	}

	groups := normalizeList(rule.APIGroups)
	if len(groups) == 0 {
		groups = []string{""}
	}

	resources := normalizeList(rule.Resources)
	if len(resources) == 0 {
		return
	}

	resourceNames := normalizeList(rule.ResourceNames)
	resourceNamesKey := ""
	if len(resourceNames) > 0 {
		resourceNamesKey = strings.Join(resourceNames, resourceNameSep)
	}

	for _, group := range groups {
		for _, resource := range resources {
			if shouldSkipRule(group, resource) {
				continue
			}
			key := ruleKey{
				apiGroup:         group,
				resource:         resource,
				resourceNamesKey: resourceNamesKey,
			}
			a.insertVerbs(key, verbs)
		}
	}
}

func shouldSkipRule(apiGroup, resource string) bool {
	return apiGroup == "policy" && resource == "podsecuritypolicies"
}

func (a *aggregator) insertVerbs(key ruleKey, verbs []string) {
	if _, ok := a.rules[key]; !ok {
		a.rules[key] = sets.New[string]()
	}
	a.rules[key].Insert(verbs...)
}

func (a *aggregator) rulesList() []rbacv1.PolicyRule {
	out := make([]rbacv1.PolicyRule, 0, len(a.rules))
	for key, verbsSet := range a.rules {
		verbs := normalizeList(sets.List(verbsSet))
		rule := rbacv1.PolicyRule{Verbs: verbs}
		if key.nonResourceURL != "" {
			rule.NonResourceURLs = []string{key.nonResourceURL}
		} else {
			rule.APIGroups = []string{key.apiGroup}
			rule.Resources = []string{key.resource}
			if key.resourceNamesKey != "" {
				rule.ResourceNames = strings.Split(key.resourceNamesKey, resourceNameSep)
			}
		}
		out = append(out, rule)
	}

	sort.Slice(out, func(i, j int) bool {
		return ruleSortKey(out[i]) < ruleSortKey(out[j])
	})
	return out
}

func ruleSortKey(rule rbacv1.PolicyRule) string {
	if len(rule.NonResourceURLs) > 0 {
		return "z|" + rule.NonResourceURLs[0]
	}
	return "a|" + rule.APIGroups[0] + "|" + rule.Resources[0] + "|" + strings.Join(rule.ResourceNames, resourceNameSep)
}

func normalizeList(items []string) []string {
	set := sets.NewString(items...)
	if set.Has("*") {
		return []string{"*"}
	}
	return set.List()
}

func main() {
	dir := ""
	name := "aggregated"
	output := ""
	charts := []string{}

	flag.StringVar(&dir, "dir", dir, "Path to directory containing Role or ClusterRole YAML files")
	flag.StringVar(&name, "name", name, "Name for the aggregated ClusterRole")
	flag.StringVar(&output, "output", output, "Write output to a file instead of stdout")
	flag.StringSliceVar(&charts, "chart", charts, "Path to one or more Helm chart directories to render and aggregate Role or ClusterRole YAMLs from")
	flag.Parse()

	agg := newAggregator()
	if dir != "" {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			return processFile(path, agg)
		})
		if err != nil {
			panic(err)
		}
	}

	for _, chartDir := range charts {
		if err := processChart(chartDir, agg); err != nil {
			panic(err)
		}
	}

	clusterRole := rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRole",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Rules: agg.rulesList(),
	}

	data, err := yaml.Marshal(clusterRole)
	if err != nil {
		panic(err)
	}

	if output == "" {
		_, _ = os.Stdout.Write(data)
		return
	}

	if err := os.WriteFile(output, data, 0o644); err != nil {
		panic(err)
	}
}

func processFile(path string, agg *aggregator) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return processManifest(path, data, agg)
}

func processChart(chartDir string, agg *aggregator) error {
	releaseName := filepath.Base(filepath.Clean(chartDir))
	if releaseName == "." || releaseName == string(filepath.Separator) || releaseName == "" {
		releaseName = "release"
	}

	cmd := exec.Command("helm", "template", releaseName, chartDir)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("helm template %s: %s", chartDir, strings.TrimSpace(string(ee.Stderr)))
		}
		return fmt.Errorf("helm template %s: %w", chartDir, err)
	}

	return processManifest("helm template "+chartDir, out, agg)
}

func processManifest(source string, data []byte, agg *aggregator) error {
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	for {
		var raw map[string]any
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("decode %s: %w", source, err)
		}
		if len(raw) == 0 {
			continue
		}

		obj := &unstructured.Unstructured{Object: raw}
		switch obj.GetKind() {
		case "ClusterRole":
			var cr rbacv1.ClusterRole
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &cr); err != nil {
				return fmt.Errorf("convert %s: %w", source, err)
			}
			for _, rule := range cr.Rules {
				agg.addRule(rule)
			}
		case "Role":
			var role rbacv1.Role
			if err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &role); err != nil {
				return fmt.Errorf("convert %s: %w", source, err)
			}
			for _, rule := range role.Rules {
				agg.addRule(rule)
			}
		default:
			continue
		}
	}

	return nil
}
