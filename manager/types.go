package manager

type (
	Domain struct {
		Name        string `json:"name,omitempty"`
		Description string `json:"description,omitempty"`
		Prefix      string `json:"prefix,omitempty"`
		Endpoint    string `json:"endpoint,omitempty"`
	}
)
