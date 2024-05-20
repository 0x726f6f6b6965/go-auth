package mask

import (
	"testing"

	"github.com/iancoleman/strcase"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestGetValueByMask(t *testing.T) {
	req := struct {
		A struct {
			B struct {
				C string
				D int
			}
		}
	}{
		A: struct {
			B struct {
				C string
				D int
			}
		}{
			B: struct {
				C string
				D int
			}{
				C: "1",
				D: 5,
			},
		},
	}
	t.Run("success", func(t *testing.T) {
		updateMask := &fieldmaskpb.FieldMask{
			Paths: []string{"a.b.c", "a.b.d"},
		}
		data, err := GetValueByMask(req, updateMask, strcase.ToCamel)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, 2, len(data))
		assert.Equal(t, "1", data["a.b.c"].(string))
		assert.Equal(t, 5, data["a.b.d"].(int))
	})

	t.Run("field name error", func(t *testing.T) {
		updateMask := &fieldmaskpb.FieldMask{
			Paths: []string{"a.b.c", ""},
		}

		_, err := GetValueByMask(req, updateMask, strcase.ToCamel)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrFieldName)
	})

	t.Run("field value error", func(t *testing.T) {
		updateMask := &fieldmaskpb.FieldMask{
			Paths: []string{"a.b.c", "a.b.e"},
		}
		_, err := GetValueByMask(req, updateMask, strcase.ToCamel)
		assert.NotNil(t, err)
		assert.ErrorIs(t, err, ErrFildValue)
	})
}
