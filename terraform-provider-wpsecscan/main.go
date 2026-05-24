// Round-64 #133 — Terraform provider stub for WPSecScan.
// Real implementation would build with hashicorp/terraform-plugin-framework.
// This file is a sketch of the resource API.

package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// WPSecScanProvider implements provider.Provider
type WPSecScanProvider struct{}

func (p *WPSecScanProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "wpsecscan"
	resp.Version = "2.2.0"
}

func (p *WPSecScanProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		func() resource.Resource { return &SiteResource{} },
	}
}

func (p *WPSecScanProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// SiteResource — `wpsecscan_site` resource.
type SiteResource struct{}

func (r *SiteResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_site"
}

func (r *SiteResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id":        schema.StringAttribute{Computed: true},
			"url":       schema.StringAttribute{Required: true},
			"name":      schema.StringAttribute{Required: true},
			"aggressive": schema.BoolAttribute{Optional: true},
			"scan_interval_hours": schema.Int64Attribute{Optional: true},
			"notify_slack_webhook": schema.StringAttribute{Optional: true, Sensitive: true},
		},
	}
}

// Create / Read / Update / Delete stubs — wire to daemon REST API
func (r *SiteResource) Create(_ context.Context, _ resource.CreateRequest, _ *resource.CreateResponse) {}
func (r *SiteResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse)         {}
func (r *SiteResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse)   {}
func (r *SiteResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse)   {}

func main() {
	fmt.Println("terraform-provider-wpsecscan v2.2.0 (stub)")
}

// Example usage in HCL:
//
//   terraform {
//     required_providers {
//       wpsecscan = {
//         source  = "bryanflowers/wpsecscan"
//         version = "~> 2.2"
//       }
//     }
//   }
//
//   resource "wpsecscan_site" "example" {
//     name = "example-com"
//     url  = "https://example.com"
//     aggressive = false
//     scan_interval_hours = 24
//     notify_slack_webhook = var.slack_webhook
//   }
