package account

type Profile struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	// We do not store account password here, it's on the database
	Gender Gender `json:"gender"`
}
