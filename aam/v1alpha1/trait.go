package v1alpha1

type Trait struct {
	ApiVersion string
	Kind       string
	Metadata   struct{
		Name string
		Annotations map[string]string
	}
	Spec struct{
		Parameter interface{}
	}
}
