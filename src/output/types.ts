export type OutputFormat = "terminal" | "json" | "sarif";

export interface OutputOptions {
  format: OutputFormat;
  noColor?: boolean;
}
