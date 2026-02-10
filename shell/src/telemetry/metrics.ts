export class Metrics {
  heartbeatsAccepted = 0;
  heartbeatsRejected = 0;
  daChallenges = 0;
  daResponses = 0;
  receiptsBuilt = 0;
  receiptsSubmitted = 0;

  inc(name: keyof Metrics): void {
    // @ts-expect-error index
    this[name] += 1;
  }
}

