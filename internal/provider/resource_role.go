/*
Copyright 2023 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	iamv2 "chainguard.dev/sdk/proto/chainguard/platform/iam/v2beta1"
	"chainguard.dev/sdk/uidp"
	"github.com/chainguard-dev/terraform-provider-chainguard/internal/validators"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource                = &roleResource{}
	_ resource.ResourceWithConfigure   = &roleResource{}
	_ resource.ResourceWithImportState = &roleResource{}
)

// NewRoleResource is a helper function to simplify the provider implementation.
func NewRoleResource() resource.Resource {
	return &roleResource{}
}

// roleResource is the resource implementation.
type roleResource struct {
	managedResource
}

type roleResourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
	Description  types.String `tfsdk:"description"`
	ParentID     types.String `tfsdk:"parent_id"`
	Capabilities types.Set    `tfsdk:"capabilities"`
}

func (r *roleResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.configure(ctx, req, resp)
}

// Metadata returns the resource type name.
func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

// Schema defines the schema for the resource.
func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "IAM Role in the Chainguard platform.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description:   "The UIDP of this role.",
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Description: "The name of this role.",
				Required:    true,
			},
			"description": schema.StringAttribute{
				Description: "An optional longer description of this role.",
				Optional:    true,
			},
			"parent_id": schema.StringAttribute{
				Description:   "The group containing this role",
				Required:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"capabilities": schema.SetAttribute{
				Description: "The list of capabilities to grant this role",
				Required:    true,
				ElementType: types.StringType,
				Validators: []validator.Set{
					setvalidator.SizeAtLeast(1),
					setvalidator.ValueStringsAre(validators.Capability()),
				},
			},
		},
	}
}

// ImportState imports resources by ID into the current Terraform state.
func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Create creates the resource and sets the initial Terraform state.
func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Read the plan data into the resource model.
	var plan roleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, fmt.Sprintf("create role request: name=%s, parent_id=%s", plan.Name, plan.ParentID))

	caps, diags := parseCapabilities(ctx, plan.Capabilities)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	role, err := retryOnPermissionDenied(ctx, func() (*iamv2.Role, error) {
		return r.prov.clientV2.IAM().RolesService().CreateRole(ctx, &iamv2.CreateRoleRequest{
			Parent: plan.ParentID.ValueString(),
			Role: &iamv2.Role{
				Name:         plan.Name.ValueString(),
				Description:  plan.Description.ValueString(),
				Capabilities: caps,
			},
		})
	})
	if err != nil {
		resp.Diagnostics.Append(errorToDiagnostic(err, "failed to create role"))
		return
	}

	plan.ID = types.StringValue(role.GetUid())
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state with the latest data.
func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Read the current state into the resource model.
	var state roleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, fmt.Sprintf("read role request: %s", state.ID))

	roleID := state.ID.ValueString()
	role, err := r.prov.clientV2.IAM().RolesService().GetRole(ctx, &iamv2.GetRoleRequest{
		Uid: roleID,
	})
	if err != nil {
		if isNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.Append(errorToDiagnostic(err, "failed to get role"))
		return
	}

	state.ID = types.StringValue(role.GetUid())
	state.Name = types.StringValue(role.GetName())
	state.Description = types.StringValue(role.GetDescription())
	state.ParentID = types.StringValue(uidp.Parent(role.GetUid()))

	var diags diag.Diagnostics
	state.Capabilities, diags = types.SetValueFrom(ctx, types.StringType, capabilityStrings(role.GetCapabilities()))
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Read the plan into the resource model.
	var data roleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, fmt.Sprintf("update role request: %s", data.ID))

	caps, diags := parseCapabilities(ctx, data.Capabilities)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	role, err := r.prov.clientV2.IAM().RolesService().UpdateRole(ctx, &iamv2.UpdateRoleRequest{
		Role: &iamv2.Role{
			Uid:          data.ID.ValueString(),
			Name:         data.Name.ValueString(),
			Description:  data.Description.ValueString(),
			Capabilities: caps,
		},
	})
	if err != nil {
		resp.Diagnostics.Append(errorToDiagnostic(err, fmt.Sprintf("failed to update role %q", data.ID.ValueString())))
		return
	}

	data.ID = types.StringValue(role.GetUid())
	data.Name = types.StringValue(role.GetName())
	data.Description = types.StringValue(role.GetDescription())
	data.Capabilities, diags = types.SetValueFrom(ctx, types.StringType, capabilityStrings(role.GetCapabilities()))
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// Read the current state into the resource model.
	var state roleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Info(ctx, fmt.Sprintf("delete role request: %s", state.ID))

	id := state.ID.ValueString()
	_, err := r.prov.clientV2.IAM().RolesService().DeleteRole(ctx, &iamv2.DeleteRoleRequest{
		Uid: id,
	})
	if err != nil {
		resp.Diagnostics.Append(errorToDiagnostic(err, fmt.Sprintf("failed to delete role %q", id)))
		return
	}
}
