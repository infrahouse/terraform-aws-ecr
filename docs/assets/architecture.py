#!/usr/bin/env python3
"""
Generate the diagrams of the terraform-aws-ecr module, from what its Terraform and Lambda code do.

Requirements:
    pip install diagrams    # and Graphviz, for the dot command

Usage:
    cd docs/assets && python architecture.py

Output, in the current directory:
    architecture.png     what the module creates, and what reads and writes the repository
    cleanup-run.png      one run of the vulnerable image cleanup
"""

from diagrams import Cluster, Diagram, Edge
from diagrams.aws.compute import ECR, ElasticContainerServiceService, Lambda
from diagrams.aws.integration import SNS, Eventbridge
from diagrams.aws.management import CloudwatchAlarm, CloudwatchLogs
from diagrams.aws.security import IAMPermissions, Inspector
from diagrams.onprem.ci import GithubActions
from diagrams.onprem.client import Users
from diagrams.programming.flowchart import Decision

FONTSIZE = "16"

# The fonts of the MkDocs Material theme, larger for readability.
GRAPH_ATTR = {
    "splines": "spline",
    "nodesep": "1.0",
    "ranksep": "1.4",
    "fontsize": FONTSIZE,
    "fontname": "Roboto",
    "dpi": "200",
}
NODE_ATTR = {"fontname": "Roboto", "fontsize": FONTSIZE}
EDGE_ATTR = {"fontname": "Roboto", "fontsize": FONTSIZE}


def overview() -> None:
    """
    What the module creates, and what reads and writes the repository.
    """
    with Diagram(
        "terraform-aws-ecr",
        filename="architecture",
        show=False,
        direction="LR",
        graph_attr=GRAPH_ATTR,
        node_attr=NODE_ATTR,
        edge_attr=EDGE_ATTR,
        outformat="png",
    ):
        ci = GithubActions("\nCI")
        people = Users("\nAlarm emails")

        with Cluster("AWS account and Region"):
            service = ElasticContainerServiceService("\nECS service")
            inspector = Inspector("\nAmazon Inspector")

            with Cluster("Created by the module"):
                repository = ECR("\nECR repository\nand lifecycle policy")

                with Cluster("Vulnerable image cleanup (opt-in)"):
                    schedule = Eventbridge("\nEventBridge rule")
                    function = Lambda("\nCleanup Lambda")
                    policy = IAMPermissions("\nIAM policy")
                    logs = CloudwatchLogs("\nLog group")
                    alarm = CloudwatchAlarm("\nAlarms")
                    topic = SNS("\nSNS topic")

        ci >> Edge(label="push") >> repository
        repository >> Edge(label="pull") >> service
        service >> Edge(label="tag deployed-at-*", style="dashed") >> repository
        inspector >> Edge(label="scan", style="dashed") >> repository

        schedule >> Edge(label="daily") >> function
        policy >> Edge(style="dotted") >> function
        function >> Edge(label="read findings\nand coverage") >> inspector
        function >> Edge(label="read; delete\nwhen not dry") >> repository
        function >> logs
        function >> alarm >> topic >> people


def cleanup_run() -> None:
    """
    One run of the vulnerable image cleanup, in order.
    """
    with Diagram(
        "One run of the vulnerable image cleanup",
        filename="cleanup-run",
        show=False,
        direction="LR",
        graph_attr=GRAPH_ATTR,
        node_attr=NODE_ATTR,
        edge_attr=EDGE_ATTR,
        outformat="png",
    ):
        schedule = Eventbridge("\nEventBridge rule\nrate(1 day)")
        function = Lambda("\nCleanup Lambda")

        images = ECR(
            "\n2. Read ECR\nDescribeImages: every image\nBatchGetImage: every index"
        )
        findings = Inspector(
            "\n2. Read Inspector\nListFindings: ACTIVE, at or\nabove the least severity,\nfix available"
            "\nListCoverage: in-use data"
        )
        decide = Decision(
            "\n\n\n3. Decide\nan index and its manifests\nare one image; what\nprotects each one"
        )
        recheck = ECR(
            "\n4. Read again the candidates'\nnever-pulled images:\n13 times, 10 s apart"
        )
        judge = Decision("\n\n\nJudge again with\nany pull found")
        delete = ECR(
            "\n5. BatchDeleteImage\nthe index, then its manifests;\noldest first, up to the cap"
        )
        logs = CloudwatchLogs(
            "\n5. Log JSON lines\nwould_delete or deleted,\nkept, left_by_cap, summary"
        )
        alarm = CloudwatchAlarm(
            "\nError alarm\nany error fails the run\nbefore it deletes"
        )

        schedule >> Edge(label="1. invoke") >> function
        function >> images
        function >> findings
        images >> decide
        findings >> decide
        decide >> Edge(label="candidates") >> recheck >> judge
        judge >> Edge(label="dry run off", color="red") >> delete
        judge >> Edge(label="every run") >> logs
        function >> Edge(label="error", color="red", style="dashed") >> alarm


if __name__ == "__main__":
    overview()
    cleanup_run()
