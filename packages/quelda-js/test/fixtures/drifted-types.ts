// Deliberately out of step with the schemas: schema.test.ts checks that the
// type/schema comparison catches each kind of drift.

export interface DriftedRuleInfo {
  id: string;
  category: 'filetype' | 'postscript'; // enum missing values
  severity: string; // enum widened to string
  default_action: 'block' | 'warn' | 'off';
  locked?: boolean; // required in the schema
  stage: 'preview' | 'stable';
  since: number; // wrong type
  message: string;
  // description missing
  extra: string; // not in the schema
}
