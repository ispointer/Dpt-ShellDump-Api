using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows.Forms;

namespace WinFormsApp1
{
    public partial class Form1 : Form
    {
        private string? _lastOutputDir;

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e) { }

        private void btnBrowse1_Click(object sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog
            {
                Title = "Select DEX input file (File upload 1)",
                Filter = "DEX (*.dex)|*.dex|All files (*.*)|*.*"
            };
            if (ofd.ShowDialog(this) == DialogResult.OK)
                txtFile1.Text = ofd.FileName;
        }

        private void btnBrowse2_Click(object sender, EventArgs e)
        {
            using var ofd = new OpenFileDialog
            {
                Title = "Select code.bin (File upload 2)",
                Filter = "All files (*.*)|*.*"
            };
            if (ofd.ShowDialog(this) == DialogResult.OK)
                txtFile2.Text = ofd.FileName;
        }

        private void btnDump_Click(object sender, EventArgs e)
        {
            try
            {
                if (!File.Exists(txtFile1.Text))
                {
                    MessageBox.Show("File upload 1 path invalid.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (!File.Exists(txtFile2.Text))
                {
                    MessageBox.Show("File upload 2 path invalid.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }

                byte[] dexInput = File.ReadAllBytes(txtFile1.Text);
                byte[] codeInput = File.ReadAllBytes(txtFile2.Text);

                var manip = new DexManipulator();
                var result = manip.RunFullPipeline(dexInput, codeInput);

                // output folder
                string baseDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    "DexDumpOutputs");

                Directory.CreateDirectory(baseDir);

                string outDir = Path.Combine(baseDir, DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                Directory.CreateDirectory(outDir);

                // save patched dex files
                string dexOutDir = Path.Combine(outDir, "dex");
                Directory.CreateDirectory(dexOutDir);

                foreach (var kv in result.DexBuffers)
                {
                    // kv.Key may contain subfolders from zip; keep only file name
                    string fileName = Path.GetFileName(kv.Key);
                    File.WriteAllBytes(Path.Combine(dexOutDir, fileName), kv.Value);
                }

                // save json files
                string jsonOutDir = Path.Combine(outDir, "json");
                Directory.CreateDirectory(jsonOutDir);

                foreach (var kv in result.JsonBuffers)
                {
                    string fileName = Path.GetFileName(kv.Key);
                    File.WriteAllText(Path.Combine(jsonOutDir, fileName), kv.Value);
                }

                // save summary
                string summaryPath = Path.Combine(outDir, "summary.json");
                File.WriteAllText(summaryPath, JsonSerializer.Serialize(result.Summary, new JsonSerializerOptions
                {
                    WriteIndented = true
                }));

                _lastOutputDir = outDir;

                MessageBox.Show(
                    $"Done!\n\nOutput: {outDir}\nPatched dex: {result.Summary.Restored.Count}\nElapsed: {result.Summary.ElapsedSeconds}s",
                    "Dump",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString(), "Dump failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void btnDumpLocate_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrWhiteSpace(_lastOutputDir) || !Directory.Exists(_lastOutputDir))
            {
                MessageBox.Show("No output folder yet. Click Dump first.", "Dump locate",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = _lastOutputDir,
                UseShellExecute = true
            });
        }
    }
}