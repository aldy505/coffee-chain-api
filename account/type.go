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
