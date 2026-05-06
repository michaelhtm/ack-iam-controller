// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package role

import (
	"context"
	"encoding/json"
	"net/url"
	"reflect"

	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	svcsdk "github.com/aws/aws-sdk-go-v2/service/iam"
	svcsdktypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	awsiampolicy "github.com/micahhausler/aws-iam-policy/policy"

	svcapitypes "github.com/aws-controllers-k8s/iam-controller/apis/v1alpha1"
	commonutil "github.com/aws-controllers-k8s/iam-controller/pkg/util"
)

// putRolePermissionsBoundary calls the IAM API to set a given role
// permission boundary.
func (rm *resourceManager) putRolePermissionsBoundary(
	ctx context.Context,
	r *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.putRolePermissionsBoundary")
	defer func() { exit(err) }()

	input := &svcsdk.PutRolePermissionsBoundaryInput{
		RoleName:            r.ko.Spec.Name,
		PermissionsBoundary: r.ko.Spec.PermissionsBoundary,
	}
	_, err = rm.sdkapi.PutRolePermissionsBoundary(ctx, input)
	rm.metrics.RecordAPICall("UPDATE", "PutRolePermissionsBoundary", err)
	return err
}

// deleteRolePermissionsBoundary calls the IAM API to delete a given role
// permission boundary.
func (rm *resourceManager) deleteRolePermissionsBoundary(
	ctx context.Context,
	r *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.deleteRolePermissionsBoundary")
	defer func() { exit(err) }()

	input := &svcsdk.DeleteRolePermissionsBoundaryInput{RoleName: r.ko.Spec.Name}
	_, err = rm.sdkapi.DeleteRolePermissionsBoundary(ctx, input)
	rm.metrics.RecordAPICall("UPDATE", "DeleteRolePermissionsBoundary", err)
	return err
}

// syncRolePermissionsBoundary synchronises role permissions boundary
func (rm *resourceManager) syncRolePermissionsBoundary(
	ctx context.Context,
	r *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.syncRolePermissionsBoundary")
	defer func() { exit(err) }()
	if r.ko.Spec.PermissionsBoundary == nil || *r.ko.Spec.PermissionsBoundary == "" {
		return rm.deleteRolePermissionsBoundary(ctx, r)
	}
	return rm.putRolePermissionsBoundary(ctx, r)
}

// getManagedPolicies returns the list of Policy ARNs currently attached to the
// Role
func (rm *resourceManager) getManagedPolicies(
	ctx context.Context,
	r *resource,
) ([]*string, error) {
	var err error
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.getManagedPolicies")
	defer func() { exit(err) }()

	input := &svcsdk.ListAttachedRolePoliciesInput{}
	input.RoleName = r.ko.Spec.Name
	res := []*string{}

	paginator := svcsdk.NewListAttachedRolePoliciesPaginator(rm.sdkapi, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range page.AttachedPolicies {
			res = append(res, p.PolicyArn)
		}
	}
	rm.metrics.RecordAPICall("READ_MANY", "ListAttachedRolePolicies", err)
	return res, err
}

// getInlinePolicies returns a map of inline policy name and policy docs
// currently attached to the Role.
//
// NOTE(jaypipes): There's no way around the inefficiencies of this method
// without caching stuff, and I don't think it's useful to have an unbounded
// cache for these inline policy documents :( IAM's ListRolePolicies API call
// only returns the *policy names* of inline policies. You need to call
// GetRolePolicy API call for each inline policy name in order to get the
// policy document. Yes, they force an O(N) time complexity for this
// operation...
func (rm *resourceManager) getInlinePolicies(
	ctx context.Context,
	r *resource,
) (map[string]*string, error) {
	var err error
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.getInlinePolicies")
	defer func() { exit(err) }()

	roleName := r.ko.Spec.Name

	input := &svcsdk.ListRolePoliciesInput{}
	input.RoleName = roleName
	res := map[string]*string{}

	paginator := svcsdk.NewListRolePoliciesPaginator(rm.sdkapi, input)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range page.PolicyNames {
			res[p] = nil
		}
	}
	rm.metrics.RecordAPICall("READ_MANY", "ListRolePolicies", err)

	// Now we need to grab the policy documents for each policy name
	for polName, _ := range res {
		input := &svcsdk.GetRolePolicyInput{}
		input.RoleName = roleName
		input.PolicyName = &polName
		resp, err := rm.sdkapi.GetRolePolicy(ctx, input)
		rm.metrics.RecordAPICall("READ_ONE", "GetRolePolicy", err)
		if err != nil {
			return nil, err
		}
		cleanedDoc, err := decodeDocument(*resp.PolicyDocument)
		if err != nil {
			return nil, err
		}
		res[polName] = &cleanedDoc

	}
	return res, nil
}

// customPreCompare contains logic that help compare two iam Roles. This
// function is injected in newResourceDelta function.
func customPreCompare(
	delta *ackcompare.Delta,
	a *resource,
	b *resource,
) {
	compareTags(delta, a, b)
	compareAssumeRolePolicyDocument(delta, a, b)
}

// compareTags is a custom comparison function for comparing lists of Tag
// structs where the order of the structs in the list is not important.
func compareTags(
	delta *ackcompare.Delta,
	a *resource,
	b *resource,
) {
	if len(a.ko.Spec.Tags) != len(b.ko.Spec.Tags) {
		delta.Add("Spec.Tags", a.ko.Spec.Tags, b.ko.Spec.Tags)
	} else if len(a.ko.Spec.Tags) > 0 {
		if !commonutil.EqualTags(a.ko.Spec.Tags, b.ko.Spec.Tags) {
			delta.Add("Spec.Tags", a.ko.Spec.Tags, b.ko.Spec.Tags)
		}
	}
}

// compareAssumeRolePolicyDocument is a custom comparison function for
// assumeRolePolicyDocuments. The reason why we need a custom function for
// this fields is the API logic that trims all the trailing while spaces
// string of provided documents.
func compareAssumeRolePolicyDocument(
	delta *ackcompare.Delta,
	a *resource,
	b *resource,
) {
	// To handle the variability in shapes of JSON objects representing IAM policies,
	// especially when it comes to statements, actions, and other fields, we need
	// a custom json.Unmarshaller approach crafted to our specific needs. Luckily,
	// it happens that @micahhausler buildta library dedicated to this very special
	// need: github.com/micahhausler/aws-iam-policy.
	//
	// NOTE(a-hilaly): I'm pretty aware that there is an error that should be handled.
	// However, unfortunetly, the `newResourceDelta` cannot return errors (for now),
	// leaving us with only two solutions, panicking or ignoring the error. The first
	// solution is an overkill as it will interrupt all the goroutines from functioning
	// and causing the controller to enter in a 'CrashLoopBackOff' state, which is not
	// fair, given that it's also is responsible of managing multiple objects of other
	// different resources.
	//
	// TOOD(a-hilaly): To address this issue, concider changing the delta signature
	// to return an error or take a context.Context to use the runtime logger. Both
	// of these changes require runtime/code-generator changes.
	var policyDocumentA awsiampolicy.Policy
	_ = json.Unmarshal([]byte(*a.ko.Spec.AssumeRolePolicyDocument), &policyDocumentA)
	var policyDocumentB awsiampolicy.Policy
	_ = json.Unmarshal([]byte(*b.ko.Spec.AssumeRolePolicyDocument), &policyDocumentB)

	if !reflect.DeepEqual(policyDocumentA, policyDocumentB) {
		delta.Add("Spec.AssumeRolePolicyDocument", a.ko.Spec.AssumeRolePolicyDocument, b.ko.Spec.AssumeRolePolicyDocument)
	}
}

// syncTags examines the Tags in the supplied Role and calls the ListRoleTags,
// TagRole and UntagRole APIs to ensure that the set of associated Tags  stays
// in sync with the Role.Spec.Tags
func (rm *resourceManager) syncTags(
	ctx context.Context,
	desired *resource,
	latest *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.syncTags")
	defer func() { exit(err) }()
	toAdd := []*svcapitypes.Tag{}
	toDelete := []*svcapitypes.Tag{}

	existingTags := latest.ko.Spec.Tags

	for _, t := range desired.ko.Spec.Tags {
		if !inTags(*t.Key, *t.Value, existingTags) {
			toAdd = append(toAdd, t)
		}
	}

	for _, t := range existingTags {
		if !inTags(*t.Key, *t.Value, desired.ko.Spec.Tags) {
			toDelete = append(toDelete, t)
		}
	}

	if len(toAdd) > 0 {
		for _, t := range toAdd {
			rlog.Debug("adding tag to role", "key", *t.Key, "value", *t.Value)
		}
		if err = rm.addTags(ctx, desired, toAdd); err != nil {
			return err
		}
	}
	if len(toDelete) > 0 {
		for _, t := range toDelete {
			rlog.Debug("removing tag from role", "key", *t.Key, "value", *t.Value)
		}
		if err = rm.removeTags(ctx, desired, toDelete); err != nil {
			return err
		}
	}

	return nil
}

// inTags returns true if the supplied key and value can be found in the
// supplied list of Tag structs.
//
// TODO(jaypipes): When we finally standardize Tag handling in ACK, move this
// to the ACK common runtime/ or pkg/ repos
func inTags(
	key string,
	value string,
	tags []*svcapitypes.Tag,
) bool {
	for _, t := range tags {
		if *t.Key == key && *t.Value == value {
			return true
		}
	}
	return false
}

// getTags returns the list of tags to the Role
func (rm *resourceManager) getTags(
	ctx context.Context,
	r *resource,
) ([]*svcapitypes.Tag, error) {
	var err error
	var resp *svcsdk.ListRoleTagsOutput
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.getTags")
	defer func() { exit(err) }()

	input := &svcsdk.ListRoleTagsInput{}
	input.RoleName = r.ko.Spec.Name
	res := []*svcapitypes.Tag{}

	for {
		resp, err = rm.sdkapi.ListRoleTags(ctx, input)
		if err != nil || resp == nil {
			break
		}
		for _, t := range resp.Tags {
			res = append(res, &svcapitypes.Tag{Key: t.Key, Value: t.Value})
		}
		if !resp.IsTruncated {
			break
		}
		input.Marker = resp.Marker
	}
	rm.metrics.RecordAPICall("READ_MANY", "ListRoleTags", err)
	return res, err
}

// addTags adds the supplied Tags to the supplied Role resource
func (rm *resourceManager) addTags(
	ctx context.Context,
	r *resource,
	tags []*svcapitypes.Tag,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.addTag")
	defer func() { exit(err) }()

	input := &svcsdk.TagRoleInput{}
	input.RoleName = r.ko.Spec.Name
	inTags := []svcsdktypes.Tag{}
	for _, t := range tags {
		inTags = append(inTags, svcsdktypes.Tag{Key: t.Key, Value: t.Value})
	}
	input.Tags = inTags

	_, err = rm.sdkapi.TagRole(ctx, input)
	rm.metrics.RecordAPICall("UPDATE", "TagRole", err)
	return err
}

// removeTags removes the supplied Tags from the supplied Role resource
func (rm *resourceManager) removeTags(
	ctx context.Context,
	r *resource,
	tags []*svcapitypes.Tag,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.removeTag")
	defer func() { exit(err) }()

	input := &svcsdk.UntagRoleInput{}
	input.RoleName = r.ko.Spec.Name
	inTagKeys := []string{}
	for _, t := range tags {
		inTagKeys = append(inTagKeys, *t.Key)
	}
	input.TagKeys = inTagKeys

	_, err = rm.sdkapi.UntagRole(ctx, input)
	rm.metrics.RecordAPICall("UPDATE", "UntagRole", err)
	return err
}

func decodeDocument(encoded string) (string, error) {
	return url.QueryUnescape(encoded)
}
