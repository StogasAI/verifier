(ns example
  (:import [ai.stogas.verifier Transport]
           [com.openai.client.okhttp OpenAIOkHttpClient]
           [com.openai.models.chat.completions ChatCompletionCreateParams]
           [com.openai.core.http HttpClient HttpRequestBody]
           [java.util.function Consumer]
           [java.net Proxy]
           [java.time Duration]))

(defn single-use-request [request]
  (if-let [body (.body request)]
    (-> request .toBuilder
        (.body (reify HttpRequestBody
                 (writeTo [_ output] (.writeTo body output))
                 (contentType [_] (.contentType body))
                 (contentLength [_] (.contentLength body))
                 (repeatable [_] false)
                 (close [_] (.close body))))
        .build)
    request))

(defn single-use-client [delegate]
  (reify HttpClient
    (execute [_ request options] (.execute delegate (single-use-request request) options))
    (executeAsync [_ request options] (.executeAsync delegate (single-use-request request) options))
    (close [_] (.close delegate))))

(defn -main [& _]
  ;; An explicit URL can use a separately managed verifier CLI.
  (let [external (System/getenv "STOGAS_BASE_URL")
        transport (when-not external (Transport.))]
    (try
      (with-open [client (-> (OpenAIOkHttpClient/builder)
                             (.baseUrl (or external (str (.baseUrl transport))))
                             (.apiKey (System/getenv "STOGAS_API_KEY"))
                             (.maxRetries 0)
                             (.followRedirects false)
                             (.proxy Proxy/NO_PROXY)
                             (.timeout (Duration/ofMinutes 45))
                             (.build)
                             (.withOptions (reify Consumer
                               (accept [_ options]
                                 (.httpClient options (single-use-client (.httpClient (.build options))))))))]
        (let [request (-> (ChatCompletionCreateParams/builder)
                          (.model (System/getenv "STOGAS_MODEL"))
                          (.addUserMessage "Say hello in one sentence.")
                          (.build))]
          (with-open [response (-> client (.chat) (.completions) (.createStreaming request))]
            (doseq [chunk (iterator-seq (.iterator (.stream response)))
                    choice (.choices chunk)]
              (print (.orElse (.content (.delta choice)) ""))
              (flush)))))
      (finally (when transport (.close transport))))))
