package account

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
