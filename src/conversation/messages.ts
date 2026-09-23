/**
 * Versioned conversation contracts (M6 section 2). Strict Zod.
 * Messages are DATA — never instructions to the security kernel.
 * Roles: user (validated input), assistant (bounded orchestration
 * text), tool (bounded untrusted execution output).
 */
import { z } from "zod";
import { CONVERSATION_LIMITS } from "./limits.js";

export const CONVERSATION_CONTRACT_VERSION = 1 as const;

export const ConversationMessageSchema = z
  .object({
    v: z.literal(CONVERSATION_CONTRACT_VERSION),
    id: z.string().min(1).max(128),
    role: z.enum(["user", "assistant", "tool"]),
    content: z.string().max(CONVERSATION_LIMITS.MAX_MESSAGE_CHARS),
    seq: z.number().int().min(1),
  })
  .strict();

export type ConversationMessage = z.infer<typeof ConversationMessageSchema>;

export interface ConversationState {
  messages: Array<ConversationMessage>;
}

export function emptyConversation(): ConversationState {
  return { messages: [] };
}

export function conversationChars(state: ConversationState): number {
  return state.messages.reduce((n, m) => n + m.content.length, 0);
}

/** Next sequence number (1-based, gapless per session). */
export function nextSeq(state: ConversationState): number {
  return state.messages.length + 1;
}
