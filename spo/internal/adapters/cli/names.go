package cli

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// ErrSealed means the workspace is sealed and no passphrase was given, so its
// names cannot be listed.
var ErrSealed = errors.New("the workspace is sealed")

// nameClasses maps a class of workspace object to the artefact kinds whose
// owner names are that object's names. A name is listed when the workspace
// holds any of the kinds for it.
var nameClasses = map[string][]ports.Kind{
	uihint.ClassWallet:        {ports.AddrFile, ports.AddrVKey, ports.AddrSKey, ports.AddrHwsFile},
	uihint.ClassStake:         {ports.StakingAddr, ports.StakingVKey, ports.StakingSKey, ports.StakingHwsFile},
	uihint.ClassPool:          {ports.NodeVKey, ports.NodeSKey, ports.NodeHwsFile, ports.PoolDescriptor},
	uihint.ClassPolicy:        {ports.PolicyVKey, ports.PolicySKey, ports.PolicyHwsFile, ports.PolicyScript, ports.PolicyID},
	uihint.ClassAsset:         {ports.AssetFile},
	uihint.ClassDRep:          {ports.DRepVKey, ports.DRepSKey, ports.DRepHwsFile, ports.DRepID},
	uihint.ClassCommitteeCold: {ports.CCColdVKey, ports.CCColdSKey, ports.CCColdHwsFile, ports.CCColdHash},
	uihint.ClassCommitteeHot:  {ports.CCHotVKey, ports.CCHotSKey, ports.CCHotHwsFile, ports.CCHotHash},
	uihint.ClassVotingKey:     {ports.VotingVKey, ports.VotingSKey, ports.VotingHwsFile, ports.VotingPKey},
	uihint.ClassCalidus:       {ports.CalidusVKey, ports.CalidusSKey, ports.CalidusHwsFile, ports.CalidusID},
}

// WorkspaceNames lists the names the workspace holds, by class (the
// uihint.Class constants). It returns names only: never a record's contents,
// never a key. It asks for nothing: a sealed workspace is opened with pass,
// and with a nil pass it is not opened and ErrSealed is returned; the
// upstream layout has no passphrase and is listed directly. A directory with
// no workspace has no names (nil, nil). The workspace is closed again before
// the function returns, and the caller keeps ownership of pass.
func WorkspaceNames(ctx context.Context, d Deps, dir string, upstream, acceptRollback bool, pass *secret.Buffer) (map[string][]string, error) {
	a := newApp(d)
	a.workspace, a.upstream = dir, upstream
	var (
		st       ports.NamedStore
		anchored ports.Store
		lister   ports.SourceLister
	)
	if upstream {
		if exists(a.workspaceFile()) || d.OpenUpstream == nil {
			return nil, nil
		}
		s, err := d.OpenUpstream(dir)
		if err != nil {
			return nil, err
		}
		st, anchored = labels.Named(s), s
	} else {
		if !exists(a.workspaceFile()) {
			return nil, nil
		}
		if pass == nil {
			return nil, ErrSealed
		}
		s, err := d.Sealed.Open(a.workspaceFile(), pass, OpenOptions{AcceptRollback: acceptRollback})
		if err != nil {
			return nil, err
		}
		defer s.Close()
		st, anchored = labels.Named(s), s
	}
	lister, ok := st.(ports.SourceLister)
	if !ok {
		return nil, errors.New("this workspace's store cannot list its names")
	}
	listing, err := lister.List(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for class, kinds := range nameClasses {
		set := map[string]bool{}
		for _, e := range listing.Entries {
			for _, k := range kinds {
				if e.Ref.Kind == k {
					name := e.Ref.Name
					if class == uihint.ClassWallet || class == uihint.ClassStake {
						name = strings.TrimSuffix(name, ".payment")
					}
					set[name] = true
				}
			}
		}
		out[class] = sortedKeys(set)
	}
	out[uihint.ClassParty] = partyNames(ctx, d, a, st, anchored)
	return out, nil
}

// partyNames lists the enrolled parties of a sealed workspace; the registry
// is wired as any party command wires it, offline and without the network.
func partyNames(ctx context.Context, d Deps, a *app, st ports.NamedStore, anchored ports.Store) []string {
	if a.upstream || d.Wire == nil {
		return nil
	}
	o := WireOptions{Workspace: a.workspace, Mode: ModeOffline, Offline: true, Ctx: ctx}
	if cfg, err := d.Config.Load(a.workspace); err == nil {
		o.Config, o.HaveConfig = cfg, true
	}
	env, err := d.Wire(anchored, o)
	if err != nil || env == nil || env.Party == nil || env.Party.Registry == nil {
		return nil
	}
	var names []string
	_ = st.View(ctx, func(r ports.NamedReader) error {
		ps, err := env.Party.Registry.List(r)
		for _, p := range ps {
			names = append(names, p.Name)
		}
		return err
	})
	sort.Strings(names)
	return names
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AttachCompletion gives the shell completion of root (`spo completion`) the
// same help the TUI form has, from the same hints (uihint): names of workspace
// objects, directories, files of an extension. Names come from the workspace
// without a passphrase, so they appear for the upstream layout and not for a
// sealed workspace (a completion must not prompt). It only registers
// completion functions; no command line changes.
func AttachCompletion(root *cobra.Command, d Deps) {
	names := func(cmd *cobra.Command, class string) []string {
		dir, _ := cmd.Flags().GetString("workspace")
		upstream, _ := cmd.Flags().GetBool("upstream-layout")
		all, err := WorkspaceNames(cmd.Context(), d, dir, upstream, false, nil)
		if err != nil {
			return nil
		}
		return all[class]
	}
	complete := func(cmd *cobra.Command, h uihint.Spec, toComplete string) ([]string, cobra.ShellCompDirective) {
		switch h.Kind {
		case uihint.KindName:
			var out []string
			for _, n := range names(cmd, h.Class) {
				if strings.HasPrefix(n, toComplete) {
					out = append(out, n)
				}
			}
			return out, cobra.ShellCompDirectiveNoFileComp
		case uihint.KindDir:
			return nil, cobra.ShellCompDirectiveFilterDirs
		case uihint.KindFile, uihint.KindNewFile:
			if len(h.Exts) > 0 {
				exts := make([]string, len(h.Exts))
				for i, e := range h.Exts {
					exts[i] = strings.TrimPrefix(e, ".")
				}
				return exts, cobra.ShellCompDirectiveFilterFileExt
			}
		}
		return nil, cobra.ShellCompDirectiveDefault
	}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		pos := uihint.Positionals(c.Use)
		var hinted bool
		for _, p := range pos {
			if _, ok := uihint.OfArg(c, p.Name); ok {
				hinted = true
			}
		}
		if hinted && c.ValidArgsFunction == nil {
			c.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				i := len(args)
				if i >= len(pos) {
					if len(pos) == 0 || !pos[len(pos)-1].Repeat {
						return nil, cobra.ShellCompDirectiveNoFileComp
					}
					i = len(pos) - 1
				}
				h, ok := uihint.OfArg(cmd, pos[i].Name)
				if !ok {
					return nil, cobra.ShellCompDirectiveDefault
				}
				return complete(cmd, h, toComplete)
			}
		}
		c.Flags().VisitAll(func(f *pflag.Flag) {
			h, ok := uihint.Of(f)
			if !ok {
				return
			}
			_ = c.RegisterFlagCompletionFunc(f.Name, func(cmd *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
				return complete(cmd, h, toComplete)
			})
		})
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk(root)
}
