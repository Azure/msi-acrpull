/*
   MIT License

   Copyright (c) Microsoft Corporation.

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE
*/

package v1beta1

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ = Describe("AcrPullBinding Webhook Tests", func() {
	Context("ValidateUpdate", func() {
		It("Validate changes to AcrPullBinding", func() {
			testCases := []struct {
				old     *AcrPullBinding
				new     *AcrPullBinding
				wantErr bool
			}{
				{
					old:     createAcrBindingWithServiceAccount("old"),
					new:     createAcrBindingWithServiceAccount("new"),
					wantErr: true,
				},
				{
					old:     createAcrBindingWithServiceAccount("old"),
					new:     createAcrBindingWithServiceAccount("old"),
					wantErr: false,
				},
			}

			for _, tc := range testCases {
				err := tc.new.ValidateUpdate(tc.old)
				if tc.wantErr {
					Expect(err).To(HaveOccurred())
				} else {
					Expect(err).NotTo(HaveOccurred())
				}
			}
		})
	})
})

func createAcrBindingWithServiceAccount(serviceAccountName string) *AcrPullBinding {
	return &AcrPullBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Spec: AcrPullBindingSpec{
			ServiceAccountName: serviceAccountName,
		},
	}
}
