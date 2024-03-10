package account

type Account interface {
	GetProfile() Profile
	GetType() Type
	StoreIdentifier() int64
}

type basicAccountImplementation struct {
	p Profile
	t Type
	s int64
}

func (b basicAccountImplementation) GetProfile() Profile {
	return b.p
}

func (b basicAccountImplementation) GetType() Type {
	return b.t
}

func (b basicAccountImplementation) StoreIdentifier() int64 {
	return b.s
}

func NewBasicAccount(profile Profile, t Type, storeIdentifier int64) Account {
	return &basicAccountImplementation{
		p: profile,
		t: t,
		s: storeIdentifier,
	}
}
