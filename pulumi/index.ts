// Round-64 #135 — Pulumi component for WPSecScan deployment.
// Wraps the Docker image + a CronJob if running in Kubernetes.

import * as pulumi from "@pulumi/pulumi";
import * as k8s from "@pulumi/kubernetes";

export interface WPSecScanArgs {
  /** Target URL to scan */
  target: pulumi.Input<string>;
  /** Cron expression (default: nightly at 02:00) */
  schedule?: pulumi.Input<string>;
  /** Kubernetes namespace */
  namespace?: pulumi.Input<string>;
  /** Image tag (default: 2.2.0) */
  imageTag?: pulumi.Input<string>;
  /** Slack webhook for notifications */
  slackWebhook?: pulumi.Input<string>;
}

export class WPSecScan extends pulumi.ComponentResource {
  public readonly cronJob: k8s.batch.v1.CronJob;

  constructor(
    name: string,
    args: WPSecScanArgs,
    opts?: pulumi.ComponentResourceOptions
  ) {
    super("wpsecscan:index:WPSecScan", name, args, opts);

    const namespace = args.namespace ?? "default";
    const tag = args.imageTag ?? "2.2.0";

    this.cronJob = new k8s.batch.v1.CronJob(
      `${name}-scan`,
      {
        metadata: { namespace },
        spec: {
          schedule: args.schedule ?? "0 2 * * *",
          jobTemplate: {
            spec: {
              template: {
                spec: {
                  restartPolicy: "OnFailure",
                  containers: [
                    {
                      name: "wpsecscan",
                      image: pulumi.interpolate`ghcr.io/bryanflowers/wpsecscan:${tag}`,
                      args: ["scan", args.target as string],
                      env: args.slackWebhook
                        ? [
                            {
                              name: "WPSECSCAN_SLACK_WEBHOOK",
                              value: args.slackWebhook,
                            },
                          ]
                        : [],
                    },
                  ],
                },
              },
            },
          },
        },
      },
      { parent: this }
    );

    this.registerOutputs({ cronJob: this.cronJob });
  }
}

// Usage:
//
//   import { WPSecScan } from "./wpsecscan";
//
//   new WPSecScan("example-com", {
//     target: "https://example.com",
//     slackWebhook: process.env.SLACK_WEBHOOK,
//   });
