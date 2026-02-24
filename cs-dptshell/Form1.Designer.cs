namespace WinFormsApp1
{
    partial class Form1
    {
        private System.ComponentModel.IContainer components = null;

        private System.Windows.Forms.Label lblFile1;
        private System.Windows.Forms.TextBox txtFile1;
        private System.Windows.Forms.Button btnBrowse1;

        private System.Windows.Forms.Label lblFile2;
        private System.Windows.Forms.TextBox txtFile2;
        private System.Windows.Forms.Button btnBrowse2;

        private System.Windows.Forms.Panel separator;

        private System.Windows.Forms.Button btnDump;
        private System.Windows.Forms.Button btnDumpLocate;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
                components.Dispose();
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            lblFile1 = new Label();
            txtFile1 = new TextBox();
            btnBrowse1 = new Button();
            lblFile2 = new Label();
            txtFile2 = new TextBox();
            btnBrowse2 = new Button();
            separator = new Panel();
            btnDump = new Button();
            btnDumpLocate = new Button();
            SuspendLayout();
            // 
            // lblFile1
            // 
            lblFile1.AutoSize = true;
            lblFile1.Location = new Point(18, 22);
            lblFile1.Name = "lblFile1";
            lblFile1.Size = new Size(115, 20);
            lblFile1.TabIndex = 0;
            lblFile1.Text = "Dex File Upload";
            // 
            // txtFile1
            // 
            txtFile1.Location = new Point(18, 45);
            txtFile1.Name = "txtFile1";
            txtFile1.Size = new Size(570, 27);
            txtFile1.TabIndex = 1;
            // 
            // btnBrowse1
            // 
            btnBrowse1.Location = new Point(600, 44);
            btnBrowse1.Name = "btnBrowse1";
            btnBrowse1.Size = new Size(100, 30);
            btnBrowse1.TabIndex = 2;
            btnBrowse1.Text = "Browse...";
            btnBrowse1.UseVisualStyleBackColor = true;
            btnBrowse1.Click += btnBrowse1_Click;
            // 
            // lblFile2
            // 
            lblFile2.AutoSize = true;
            lblFile2.Location = new Point(18, 85);
            lblFile2.Name = "lblFile2";
            lblFile2.Size = new Size(179, 20);
            lblFile2.TabIndex = 3;
            lblFile2.Text = "bin or OoooOooo upload";
            // 
            // txtFile2
            // 
            txtFile2.Location = new Point(18, 108);
            txtFile2.Name = "txtFile2";
            txtFile2.Size = new Size(570, 27);
            txtFile2.TabIndex = 4;
            // 
            // btnBrowse2
            // 
            btnBrowse2.Location = new Point(600, 107);
            btnBrowse2.Name = "btnBrowse2";
            btnBrowse2.Size = new Size(100, 30);
            btnBrowse2.TabIndex = 5;
            btnBrowse2.Text = "Browse...";
            btnBrowse2.UseVisualStyleBackColor = true;
            btnBrowse2.Click += btnBrowse2_Click;
            // 
            // separator
            // 
            separator.BorderStyle = BorderStyle.FixedSingle;
            separator.Location = new Point(18, 154);
            separator.Name = "separator";
            separator.Size = new Size(682, 2);
            separator.TabIndex = 6;
            // 
            // btnDump
            // 
            btnDump.Location = new Point(18, 170);
            btnDump.Name = "btnDump";
            btnDump.Size = new Size(332, 36);
            btnDump.TabIndex = 7;
            btnDump.Text = "Dump";
            btnDump.UseVisualStyleBackColor = true;
            btnDump.Click += btnDump_Click;
            // 
            // btnDumpLocate
            // 
            btnDumpLocate.Location = new Point(368, 170);
            btnDumpLocate.Name = "btnDumpLocate";
            btnDumpLocate.Size = new Size(332, 36);
            btnDumpLocate.TabIndex = 8;
            btnDumpLocate.Text = "Dump locate";
            btnDumpLocate.UseVisualStyleBackColor = true;
            btnDumpLocate.Click += btnDumpLocate_Click;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(8F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(720, 220);
            Controls.Add(lblFile1);
            Controls.Add(txtFile1);
            Controls.Add(btnBrowse1);
            Controls.Add(lblFile2);
            Controls.Add(txtFile2);
            Controls.Add(btnBrowse2);
            Controls.Add(separator);
            Controls.Add(btnDump);
            Controls.Add(btnDumpLocate);
            Name = "Form1";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "CS-DPTShell";
            Load += Form1_Load;
            ResumeLayout(false);
            PerformLayout();
        }
    }
}