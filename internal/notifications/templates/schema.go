package templates

type Channel string

const (
	ChannelEmail Channel = "email"
	ChannelTeams Channel = "teams"
)

type VariableType string

const (
	TypeString     VariableType = "string"
	TypeNumber     VariableType = "number"
	TypeBoolean    VariableType = "boolean"
	TypeStringList VariableType = "string_list"
	TypeURL        VariableType = "url"
)

type RedactionPolicy string

const (
	RedactNone   RedactionPolicy = "none"
	RedactSecret RedactionPolicy = "secret"
	RedactURL    RedactionPolicy = "url"
)

type Template struct {
	ID                 string              `json:"id"`
	Version            string              `json:"version"`
	Description        string              `json:"description"`
	CompatibleChannels []Channel           `json:"compatible_channels"`
	Variables          map[string]Variable `json:"variables"`
	Targets            Targets             `json:"targets"`
}

type Variable struct {
	Type        VariableType    `json:"type"`
	Required    bool            `json:"required"`
	Redaction   RedactionPolicy `json:"redaction"`
	Description string          `json:"description"`
}

type Targets struct {
	Email *EmailTargets `json:"email,omitempty"`
	Teams *TeamsTargets `json:"teams,omitempty"`
}

type EmailTargets struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

type TeamsTargets struct {
	CardJSON string `json:"card_json"`
}

type Rendered struct {
	Email *RenderedEmail `json:"email,omitempty"`
	Teams *RenderedTeams `json:"teams,omitempty"`
}

type RenderedEmail struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

type RenderedTeams struct {
	CardJSON string `json:"card_json"`
}
