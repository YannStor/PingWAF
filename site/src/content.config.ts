import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

/**
 * Long-form documentation lives in `src/content/docs/<locale>/<slug>.md` so it
 * is authored as prose, while marketing copy stays in typed TS modules.
 */
const docs = defineCollection({
  loader: glob({ base: "./src/content/docs", pattern: "**/*.md" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    minutes: z.number().int().positive(),
  }),
});

export const collections = { docs };
