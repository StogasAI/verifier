import os

from openai import DefaultHttpxClient, OpenAI
from stogas_verifier import Transport


def client(base_url: str, api_key: str) -> OpenAI:
    return OpenAI(
        api_key=api_key,
        base_url=base_url,
        max_retries=0,
        http_client=DefaultHttpxClient(
            trust_env=False, follow_redirects=False, timeout=45 * 60
        ),
    )


def main() -> None:
    api_key = os.environ["STOGAS_API_KEY"]
    model = os.environ["STOGAS_MODEL"]
    transport = Transport()
    try:
        with client(transport.base_url, api_key) as api:
            with api.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Say hello in one sentence."}],
                stream=True,
            ) as stream:
                for chunk in stream:
                    for choice in chunk.choices:
                        if choice.delta.content:
                            print(choice.delta.content, end="", flush=True)
            print()
    finally:
        transport.close()


if __name__ == "__main__":
    main()
