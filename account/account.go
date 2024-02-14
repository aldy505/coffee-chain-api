package account

type Account interface {
	GetProfile() Profile
	Type() Type
	StoreIdentifier() int64
}
