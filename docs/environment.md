# Environment Setup

Create a `.env` file in the project root:

```bash
nano .env
```

Minimum for chat (OpenRouter):

```env
CHATBOTTOKEN=sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
YOUR_SITE_URL=http://localhost:3000
YOUR_SITE_NAME=Chatty
```

Get this key from: https://openrouter.ai/keys

Free image generation (recommended default):

```env
IMAGE_PROVIDER=pollinations
POLLINATIONS_IMAGE_MODEL=flux
```

No key is required for basic usage.

Optional Pollinations key (for higher limits / account-based usage):

```env
POLLINATIONS_API_KEY=your_pollinations_key
```

Optional paid image generation (OpenAI-compatible):

```env
IMAGE_PROVIDER=openai
OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
IMAGE_MODEL=gpt-image-1
```

Get this key from: https://platform.openai.com/api-keys

Optional advanced image provider override (OpenAI-compatible only):

```env
IMAGE_API_KEY=your-provider-key
IMAGE_API_BASE_URL=https://api.openai.com/v1
```
