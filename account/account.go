package account

type Type uint8

const (
	TypeUnspecified Type = iota
	TypeCustomer
	TypeMerchantCashier
	TypeManagement
)

func (a Type) String() string {
	switch a {
	case TypeUnspecified:
		return ""
	case TypeCustomer:
		return "Customer"
	case TypeMerchantCashier:
		return "Merchant Cashier"
	case TypeManagement:
		return "Management"
	default:
		return ""
	}
}

type Gender uint8

const (
	GenderUnspecified Gender = iota
	GenderMale
	GenderFemale
	GenderOthers
)

func (g Gender) String() string {
	switch g {
	case GenderUnspecified:
		return ""
	case GenderMale:
		return "Male"
	case GenderFemale:
		return "Female"
	case GenderOthers:
		return "Others"
	default:
		return ""
	}
}

type Profile struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	// We do not store account password here, it's on the database
	Gender Gender `json:"gender"`
}

type Account interface {
	GetProfile() Profile
	Type() Type
	StoreIdentifier() int64
}
