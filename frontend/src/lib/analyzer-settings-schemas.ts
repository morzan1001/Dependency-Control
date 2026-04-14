/**
 * Schema-driven settings definitions per analyzer.
 *
 * Each analyzer can declare a list of configurable fields. The AnalyzerSettingsDialog
 * renders these schemas as form controls. To make a new analyzer configurable:
 * add an entry to ANALYZER_SETTINGS_SCHEMAS keyed by analyzer ID.
 */

export type AnalyzerSettingFieldType = 'select' | 'switch' | 'number' | 'slider';

export interface AnalyzerSettingSelectOption {
  value: string;
  label: string;
}

export interface AnalyzerSettingField {
  /** Backend setting key (sent in analyzer_settings[analyzer_id][key]) */
  key: string;
  /** Field type — controls which input is rendered */
  type: AnalyzerSettingFieldType;
  /** UI label */
  label: string;
  /** Optional helper text shown below the field */
  description?: string;
  /** Default value (used when project has no value set) */
  default: string | number | boolean;
  /** For 'select' type */
  options?: AnalyzerSettingSelectOption[];
  /** For 'number' / 'slider' types */
  min?: number;
  max?: number;
  step?: number;
}

export interface AnalyzerSettingsSchema {
  /** Title shown at the top of the dialog */
  title: string;
  /** Description shown below the title */
  description: string;
  /** Fields rendered in order */
  fields: AnalyzerSettingField[];
}

export const ANALYZER_SETTINGS_SCHEMAS: Record<string, AnalyzerSettingsSchema> = {
  license_compliance: {
    title: 'License Scanner Policy',
    description:
      "Configure how this project uses dependencies. The scanner uses this context to decide " +
      "which copyleft licenses are actually problematic for you — reducing noise from findings " +
      "that don't apply to your usage model.",
    fields: [
      {
        key: 'distribution_model',
        type: 'select',
        label: 'Distribution Model',
        description:
          "GPL obligations only trigger on distribution. Internal-only projects don't need to worry about GPL dependencies.",
        default: 'distributed',
        options: [
          { value: 'internal_only', label: 'Internal only — not distributed outside the organization' },
          { value: 'distributed', label: 'Distributed — binary or source shared with third parties' },
          { value: 'open_source', label: 'Open source — project itself is open source' },
        ],
      },
      {
        key: 'deployment_model',
        type: 'select',
        label: 'Deployment Model',
        description:
          'AGPL/SSPL clauses only trigger on network interaction. CLI tools and batch jobs are not affected.',
        default: 'network_facing',
        options: [
          { value: 'network_facing', label: 'Network-facing — SaaS, web app, or API' },
          { value: 'cli_batch', label: 'CLI / Batch job / Daemon' },
          { value: 'desktop', label: 'Desktop application' },
          { value: 'embedded', label: 'Embedded / IoT system' },
        ],
      },
      {
        key: 'library_usage',
        type: 'select',
        label: 'Library Usage',
        description:
          'Weak copyleft (LGPL, MPL) only requires source disclosure when you modify the library itself.',
        default: 'mixed',
        options: [
          { value: 'unmodified', label: 'Unmodified — libraries used as-is via public API' },
          { value: 'modified', label: 'Modified — libraries are forked or patched' },
          { value: 'mixed', label: 'Mixed — some modified, some not (conservative)' },
        ],
      },
      {
        key: 'allow_strong_copyleft',
        type: 'switch',
        label: 'Allow Strong Copyleft',
        description: 'Treat GPL-style licenses as informational instead of compliance issues.',
        default: false,
      },
      {
        key: 'allow_network_copyleft',
        type: 'switch',
        label: 'Allow Network Copyleft',
        description: 'Treat AGPL/SSPL licenses as lower severity instead of critical.',
        default: false,
      },
    ],
  },

  deps_dev: {
    title: 'OpenSSF Scorecard Settings',
    description:
      'Configure the OpenSSF Scorecard thresholds. Lower scores indicate higher supply-chain risk. ' +
      'Adjust the thresholds to match your risk tolerance.',
    fields: [
      {
        key: 'scorecard_threshold',
        type: 'number',
        label: 'Flag Threshold',
        description: 'Packages with a Scorecard score below this value will be flagged. Range: 0–10.',
        default: 5.0,
        min: 0,
        max: 10,
        step: 0.5,
      },
      {
        key: 'scorecard_high_threshold',
        type: 'number',
        label: 'HIGH Severity Below',
        description: 'Scores below this value get HIGH severity. Default: 2.0',
        default: 2.0,
        min: 0,
        max: 10,
        step: 0.5,
      },
      {
        key: 'scorecard_medium_threshold',
        type: 'number',
        label: 'MEDIUM Severity Below',
        description: 'Scores below this value (but above HIGH) get MEDIUM. Default: 4.0',
        default: 4.0,
        min: 0,
        max: 10,
        step: 0.5,
      },
      {
        key: 'scorecard_low_threshold',
        type: 'number',
        label: 'LOW Severity Below',
        description: 'Scores below this value (but above MEDIUM) get LOW. Default: 5.0',
        default: 5.0,
        min: 0,
        max: 10,
        step: 0.5,
      },
    ],
  },

  end_of_life: {
    title: 'End-of-Life Settings',
    description:
      'Configure when EOL components should be considered HIGH or MEDIUM severity, based on how long ago they reached end-of-life.',
    fields: [
      {
        key: 'eol_high_after_days',
        type: 'number',
        label: 'HIGH Severity After (days)',
        description: 'Components past EOL longer than this get HIGH severity. Default: 365 (1 year).',
        default: 365,
        min: 0,
        max: 3650,
        step: 30,
      },
      {
        key: 'eol_medium_after_days',
        type: 'number',
        label: 'MEDIUM Severity After (days)',
        description: 'Components past EOL longer than this get MEDIUM severity. Default: 180 (6 months).',
        default: 180,
        min: 0,
        max: 3650,
        step: 30,
      },
    ],
  },

  typosquatting: {
    title: 'Typosquatting Detection Settings',
    description:
      'Configure how aggressively to flag packages with names similar to popular packages. Higher values reduce false positives.',
    fields: [
      {
        key: 'similarity_threshold',
        type: 'number',
        label: 'Minimum Similarity (0–1)',
        description: 'Only packages above this similarity ratio are flagged. Default: 0.82',
        default: 0.82,
        min: 0.5,
        max: 1.0,
        step: 0.01,
      },
      {
        key: 'critical_similarity',
        type: 'number',
        label: 'CRITICAL Severity Above',
        description: 'Similarity above this is CRITICAL severity. Default: 0.95',
        default: 0.95,
        min: 0.5,
        max: 1.0,
        step: 0.01,
      },
      {
        key: 'high_similarity',
        type: 'number',
        label: 'HIGH Severity Above',
        description: 'Similarity above this is HIGH severity. Default: 0.90',
        default: 0.90,
        min: 0.5,
        max: 1.0,
        step: 0.01,
      },
    ],
  },

  maintainer_risk: {
    title: 'Maintainer Risk Settings',
    description:
      'Configure when packages should be flagged as stale or infrequently updated based on time since last release/push.',
    fields: [
      {
        key: 'stale_after_days',
        type: 'number',
        label: 'Stale Threshold (days)',
        description:
          'Packages without a release/push for longer than this are flagged as stale. Default: 730 (2 years).',
        default: 730,
        min: 30,
        max: 3650,
        step: 30,
      },
      {
        key: 'warn_after_days',
        type: 'number',
        label: 'Warning Threshold (days)',
        description:
          'Packages without a release for longer than this are flagged as infrequently updated. Default: 365 (1 year).',
        default: 365,
        min: 30,
        max: 3650,
        step: 30,
      },
    ],
  },
};

export function hasSettingsSchema(analyzerId: string): boolean {
  return analyzerId in ANALYZER_SETTINGS_SCHEMAS;
}

export function getSettingsSchema(analyzerId: string): AnalyzerSettingsSchema | undefined {
  return ANALYZER_SETTINGS_SCHEMAS[analyzerId];
}
