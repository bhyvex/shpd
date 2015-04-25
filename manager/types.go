package manager

type (
	Domain struct {
		Name        string `json:"name,omitempty"`
		Description string `json:"description,omitempty"`
		Domain      string `json:"domain,omitempty"`
		Endpoint    string `json:"endpoint,omitempty"`
	}
)
