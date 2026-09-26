defmodule StogasExample.MixProject do
  use Mix.Project

  def project do
    [app: :stogas_example, version: "0.1.0", elixir: "~> 1.18", deps: [{:openai_ex, "0.9.21"}]]
  end

  def application, do: [extra_applications: [:logger]]
end
