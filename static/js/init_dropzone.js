
Dropzone.options.dz = {
  autoProcessQueue: false,   // 自動アップロードしない
  parallelUploads: 10,        // 同時アップロード数
  maxFilesize: 10,           // ファイルサイズ
  dictDefaultMessage: "",
  acceptedFiles: "",
  dictDefaultMessage: "",
  dictInvalidFileType: "このファイル形式はアップロードできません",
  dictFileTooBig: "ファイルサイズが大きすぎます",

  previewTemplate: `
    <div class="dz-preview dz-file-preview position-relative
                fade show
                card shadow-sm mb-1"
        style="min-height: 80px; margin: 0; width: 200px;">

      <!-- 削除ボタン -->
      <button type="button"
              class="dz-remove btn-close position-absolute top-0 end-0 m-2"
              aria-label="削除"
              data-dz-remove></button>

      <div class="card-body text-center p-2">

        <!-- ファイル名 -->
        <div class="fw-semibold small text-break mb-1"
            data-dz-name></div>

        <!-- サイズ -->
        <div class="text-muted small"
            data-dz-size></div>

        <!-- プログレス -->
        <div class="progress mt-1" style="height: 6px;">
          <div class="progress-bar progress-bar-striped progress-bar-animated"
              role="progressbar"
              style="width: 0%;"
              data-dz-uploadprogress></div>
        </div>

        <!-- エラー -->
        <div class="dz-error-message text-danger small mt-2"
            data-dz-errormessage></div>

      </div>
    </div>
  `,

  init: function () {
      const dz = this;
      const placeholder = document.getElementById("dz-placeholder");

      // アップロードボタン押下時処理
      document.getElementById("uploadBtn").addEventListener("click", function () {
          // キューに溜まっているファイルを一括アップロード
          dz.processQueue();
      });

      // ファイル追加時文言を隠す
      this.on("addedfile", function () {
        placeholder.style.display = "none";
      });

      // ファイルが全て無くなったら文言再表示
      this.on("removedfile", function () {
        if (dz.files.length === 0) {
          placeholder.style.display = "flex";
        }
      });

      // 失敗時
      this.on("error", function (file) {
          file.previewElement.classList.add("border-red-400", "bg-red-50");
      });

      // 成功時
      this.on("success", function(file, response) {
          const preview = file.previewElement;

          // プログレスを 100% に設定
          const bar = preview.querySelector(".progress-bar");
          bar.style.width = "100%";

          // 少し待つ
          setTimeout(() => {
            // フェードアウト
            preview.classList.remove("show");

            // 更に少し待つ
            setTimeout(() => {
              
              // ドロップゾーン内のファイルを消す
              dz.removeFile(file);

              // リストに追加する
              if (window.filesApp && response) {
                window.filesApp.addFile(response);
              }
            }, 300);

          }, 200);
      });
   },
};
