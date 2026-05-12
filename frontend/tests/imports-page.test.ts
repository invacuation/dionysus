import { describe, expect, test } from "bun:test"

import {
  canUploadReport,
  datetimeLocalFromIso,
  folderForImportPath,
  folderOptionsForImport,
  importCompleteMessage,
  importsWorkspaceDescription,
  pendingImportAsset,
  pendingImportFolders,
  supportedImportReportFormats,
  toolFeedbackForReportFile,
} from "../src/features/imports/imports-page"
import type { Asset, TrivyImportPreviewResponse } from "../src/lib/api"

function asset(overrides: Partial<Asset>): Asset {
  return {
    id: "asset-1",
    parent_id: null,
    path: "asset-1",
    type: "scan_target",
    name: "Asset 1",
    target_ref: null,
    scan_label: null,
    sla_tracking_enabled: null,
    sla_reporting_enabled: null,
    sort_order: 0,
    ...overrides,
  }
}

describe("folderOptionsForImport", () => {
  test("only offers folders as import destinations", () => {
    const folder = asset({
      id: "folder-1",
      path: "images/releases",
      type: "folder",
      name: "releases",
    })
    const scanTarget = asset({
      id: "target-1",
      parent_id: folder.id,
      path: "images/releases/api",
      type: "scan_target",
      name: "API image",
    })

    expect(folderOptionsForImport([scanTarget, folder])).toEqual([folder])
  })
})

describe("importsWorkspaceDescription", () => {
  test("describes imports without naming one specific scanner", () => {
    expect(importsWorkspaceDescription()).toBe(
      "Upload supported scanner reports against existing projects and assets.",
    )
    expect(importsWorkspaceDescription()).not.toContain("Trivy")
  })
})

describe("supportedImportReportFormats", () => {
  test("lists the report formats currently accepted by imports", () => {
    expect(supportedImportReportFormats()).toEqual([
      { command: "trivy image --format json", label: "Trivy" },
    ])
  })
})

describe("toolFeedbackForReportFile", () => {
  test("stays blank until a selected report is parsed", () => {
    const preview: TrivyImportPreviewResponse = {
      scanner: "trivy",
      report_kind: "trivy-image-json",
      tool_label: "Trivy (Image)",
      detected_asset_name: "ubuntu:25.10",
      detected_target_ref: "ubuntu:25.10",
      scan_started_at: null,
      finding_count: 12,
      group_count: 3,
    }

    expect(toolFeedbackForReportFile(null)).toBe("")
    expect(toolFeedbackForReportFile(new File(["{}"], "trivy-image.json"))).toBe("")
    expect(toolFeedbackForReportFile(new File(["{}"], "trivy-image.json"), preview)).toBe(
      "Trivy (Image)",
    )
  })
})

describe("importCompleteMessage", () => {
  test("puts filename and import id in the title without repeating the scan id", () => {
    expect(
      importCompleteMessage(
        {
          import_attempt_id: "import-1",
          scan_id: "scan-1",
          project_id: "project-1",
          scan_target_id: "target-1",
          scanner: "trivy",
          report_kind: "trivy-image-json",
          finding_count: 21,
          group_count: 11,
        },
        "trivy.json",
      ),
    ).toEqual({
      title: "Import of trivy.json complete, with ID import-1.",
      body: "21 findings across 11 groups.",
    })
  })
})

describe("canUploadReport", () => {
  test("requires a parsed preview before upload is available", () => {
    const file = new File(["{}"], "trivy-image.json")

    expect(
      canUploadReport({
        hasProject: true,
        folderPath: "images/releases",
        file,
        hasSuccessfulPreview: false,
        isUploading: false,
      }),
    ).toBe(false)
    expect(
      canUploadReport({
        hasProject: true,
        folderPath: "images/releases",
        file,
        hasSuccessfulPreview: true,
        isUploading: false,
      }),
    ).toBe(true)
    expect(
      canUploadReport({
        hasProject: true,
        folderPath: " ",
        file,
        hasSuccessfulPreview: true,
        isUploading: false,
      }),
    ).toBe(true)
  })
})

describe("folderForImportPath", () => {
  test("resolves an existing folder or a pending folder for a new path", () => {
    const folder = asset({
      id: "folder-1",
      path: "ubuntu/25.10",
      type: "folder",
      name: "25.10",
    })

    expect(folderForImportPath([folder], "ubuntu/25.10")).toEqual(folder)
    expect(folderForImportPath([folder], "ubuntu/25.10/new")).toMatchObject({
      id: "__pending_import_folder__:ubuntu/25.10/new",
      path: "ubuntu/25.10/new",
      type: "folder",
      name: "new",
    })
  })

  test("keeps blank folder paths unresolved so the user can browse suggestions", () => {
    const folder = asset({
      id: "folder-1",
      path: "ubuntu/25.10",
      type: "folder",
      name: "25.10",
    })

    expect(folderForImportPath([folder], "")).toBeNull()
    expect(folderForImportPath([folder], " ")).toBeNull()
  })
})

describe("pendingImportFolders", () => {
  test("previews missing nested folders under existing folders", () => {
    const folder = asset({
      id: "folder-1",
      path: "ubuntu",
      type: "folder",
      name: "ubuntu",
    })

    expect(pendingImportFolders([folder], "ubuntu/25.10/releases")).toMatchObject([
      {
        id: "__pending_import_folder__:ubuntu/25.10",
        parent_id: folder.id,
        path: "ubuntu/25.10",
        name: "25.10",
      },
      {
        id: "__pending_import_folder__:ubuntu/25.10/releases",
        parent_id: "__pending_import_folder__:ubuntu/25.10",
        path: "ubuntu/25.10/releases",
        name: "releases",
      },
    ])
  })
})

describe("pendingImportAsset", () => {
  test("previews the pending import leaf under the selected folder", () => {
    const folder = asset({
      id: "__pending_import_folder__:ubuntu/25.10",
      path: "ubuntu/25.10",
      type: "folder",
      name: "25.10",
    })
    const preview: TrivyImportPreviewResponse = {
      scanner: "trivy",
      report_kind: "trivy-image-json",
      tool_label: "Trivy (Image)",
      detected_asset_name: "ubuntu:25.10",
      detected_target_ref: "ubuntu:25.10",
      scan_started_at: null,
      finding_count: 12,
      group_count: 3,
    }

    expect(pendingImportAsset(folder, "loren", "", preview)).toMatchObject({
      parent_id: folder.id,
      path: "ubuntu/25.10/loren",
      name: "loren",
      target_ref: "ubuntu:25.10",
      scan_label: "Trivy Image Scan",
      type: "scan_target",
    })
    expect(pendingImportAsset(folder, "", "", preview)).toMatchObject({
      path: "ubuntu/25.10/ubuntu:25.10",
      name: "ubuntu:25.10",
    })
  })

  test("previews blank folder imports at the project root", () => {
    const preview: TrivyImportPreviewResponse = {
      scanner: "trivy",
      report_kind: "trivy-image-json",
      tool_label: "Trivy (Image)",
      detected_asset_name: "postgres:latest",
      detected_target_ref: "postgres:latest",
      scan_started_at: null,
      finding_count: 12,
      group_count: 3,
    }

    expect(pendingImportAsset(null, "latest", "", preview)).toMatchObject({
      parent_id: null,
      path: "latest",
      name: "latest",
      target_ref: "postgres:latest",
    })
  })
})

describe("datetimeLocalFromIso", () => {
  test("formats parsed report timestamps for datetime-local inputs", () => {
    expect(datetimeLocalFromIso("2026-05-07T12:34:56Z")).toMatch(
      /^2026-05-07T(12|13):34$/,
    )
    expect(datetimeLocalFromIso(null)).toBe("")
    expect(datetimeLocalFromIso("not a date")).toBe("")
  })
})
