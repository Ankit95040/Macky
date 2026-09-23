/**
 * Provider abstraction (M9). The provider performs network I/O for
 * the trusted service and NOTHING else: it receives validated inert
 * data (query/maxResults, final URL) plus an abort signal, and returns
 * bounded raw payloads. It never sees grants, sleep/kill state,
 * epochs, audit handles, or security policy — those stay in the
 * service. A future real provider implements this interface without
 * touching the kernel.
 */
export interface ProviderSearchRequest {
  readonly query: string;
  readonly maxResults: number;
  readonly signal?: AbortSignal;
}

export interface ProviderSearchHit {
  readonly title: string;
  readonly url: string;
  readonly snippet: string;
}

export interface ProviderFetchRequest {
  readonly url: string;
  readonly signal?: AbortSignal;
}

export type ProviderFetchResponse =
  | { readonly status: "ok"; readonly url: string; readonly title: string; readonly body: string }
  | { readonly status: "redirect"; readonly location: string }
  | { readonly status: "error"; readonly reason: string };

export interface WebSearchProvider {
  search(request: ProviderSearchRequest): Promise<ReadonlyArray<ProviderSearchHit>>;
  fetch(request: ProviderFetchRequest): Promise<ProviderFetchResponse>;
}
