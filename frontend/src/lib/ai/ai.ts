import { useState } from "react";
import { generateText } from "ai";
import { createOpenAI } from "@ai-sdk/openai";
import { createDeepSeek } from "@ai-sdk/deepseek";
import {
    AIProvider,
    useAiApiKey,
    useAiModel,
    useAiProvider,
} from "@/lib/settings";

function createProvider(provider: AIProvider, apiKey: string) {
    switch (provider) {
        case AIProvider.OPEN_AI:
            return createOpenAI({ apiKey, compatibility: "strict" });

        case AIProvider.DEEP_SEEK:
            return createDeepSeek({ apiKey });

        default: {
            const exhaustiveCheck: never = provider;
            throw new Error(`Unknown provider: ${exhaustiveCheck}`);
        }
    }
}

export type Message = {
    role: "user" | "assistant";
    content: string;
};

export function useAI() {
    const [aiProvider] = useAiProvider();
    const [aiModel] = useAiModel();
    const [aiApiKey] = useAiApiKey();
    const [chatHistory, setChatHistory] = useState<Message[]>([]);

    const provider = createProvider(aiProvider, aiApiKey);
    const model = provider(aiModel);

    const chatSubmit = async (prompt: string) => {
        setChatHistory([
            ...chatHistory,
            { role: "user", content: prompt },
            { role: "assistant", content: "Loading..." },
        ]);

        const { text } = await generateText({
            model,
            messages: [...chatHistory, { role: "user", content: prompt }],
        });

        setChatHistory([
            ...chatHistory,
            { role: "user", content: prompt },
            { role: "assistant", content: text },
        ]);
    };

    return { chatHistory, chatSubmit };
}
