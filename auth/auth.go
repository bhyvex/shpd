package auth

type AuthToken struct {
	Username string `json:"username,omitempty"`
	Token    string `json:"token,omitempty"`
}

type Account struct {
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	Username  string `json:"username,omitempty"`
	Email     string `json:"email,omitempty"`
	Password  string `json:"password,omitempty"`
}
