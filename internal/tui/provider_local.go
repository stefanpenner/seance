package tui

import "seance/internal/session"

// LocalProvider wraps a local in-process session.Manager.
type LocalProvider struct {
	mgr      *session.Manager
	shell    string
	childEnv []string
	cwd      string
	url      string
}

func NewLocalProvider(mgr *session.Manager, shell string, childEnv []string, cwd string, url string) *LocalProvider {
	return &LocalProvider{
		mgr:      mgr,
		shell:    shell,
		childEnv: childEnv,
		cwd:      cwd,
		url:      url,
	}
}

func (p *LocalProvider) List() ([]session.Info, error) {
	return p.mgr.List(), nil
}

func (p *LocalProvider) Create(name, shell string, cols, rows uint16, env []string, parentID string) (session.Info, error) {
	if shell == "" {
		shell = p.shell
	}
	if env == nil {
		env = p.childEnv
	}
	t, err := p.mgr.Create(name, shell, cols, rows, env, parentID, p.cwd)
	if err != nil {
		return session.Info{}, err
	}
	return t.GetInfo(), nil
}

func (p *LocalProvider) Kill(id string) error {
	return p.mgr.Kill(id)
}

func (p *LocalProvider) Rename(id string, name string) error {
	return p.mgr.Rename(id, name)
}

func (p *LocalProvider) ServerURL() string {
	return p.url
}
