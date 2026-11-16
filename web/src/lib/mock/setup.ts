// The setup helper's routes in mock mode: setupcore.ts over the generated fixture.
import fixture from './setup-fixture.json';
import type { SetupFamily, SnippetBody } from '../setup';
import { snippetReply, type Reply, type SetupFixture } from './setupcore';

const FX = fixture as unknown as SetupFixture;

export function setupFamilies(): SetupFamily[] {
  return FX.families;
}

export function setupSnippet(b: SnippetBody): Reply {
  return snippetReply(FX, b);
}
