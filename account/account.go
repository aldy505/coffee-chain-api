package account

type Account interface {
	GetProfile() Profile
	GetType() Type
	StoreIdentifier() int64
}
