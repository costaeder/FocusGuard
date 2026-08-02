using System.Diagnostics;
using FocusGuard.Shared.Models;
using FocusGuard.Shared.Services;
using Microsoft.Win32;
using System.ServiceProcess;

namespace FocusGuard.Manager;

public partial class MainForm : Form
{
    private AppConfig _config = null!;
    private ComboBox _cboDns = null!;
    private TextBox _txtSite = null!;
    private Label _lblSiteCount = null!;
    private Label _lblServiceStatus = null!;
    private CheckBox _chkDryRun = null!;
    private CheckBox _chkBlockBrowsers = null!;
    private CheckBox _chkContentAnalysis = null!;
    private CheckBox _chkStartup = null!;
    private NumericUpDown _numThreshold = null!;
    private CheckBox _chkUseAi = null!;
    private TextBox _txtAiApiKey = null!;
    private ComboBox _cboAiModel = null!;
    private TextBox _txtLog = null!;
    private NotifyIcon _trayIcon = null!;
    private bool _reallyClose = false;

    public MainForm()
    {
        InitializeComponent();
        InitializeTrayIcon();
        LoadConfig();
        UpdateServiceStatus();

        // Inicia minimizado se foi passado --minimized
        if (Program.StartMinimized)
        {
            WindowState = FormWindowState.Minimized;
            ShowInTaskbar = false;
            _trayIcon.Visible = true;
            // Esconde o form no Load
            Load += (s, e) => Hide();
        }
    }

    private void InitializeComponent()
    {
        Text = "FocusGuard - Gerenciador";
        FormBorderStyle = FormBorderStyle.FixedSingle;
        StartPosition = FormStartPosition.Manual;
        MaximizeBox = false;
        ShowInTaskbar = true;
        AutoScaleMode = AutoScaleMode.Dpi;

        int margin = 20;
        int groupWidth = 530;
        int gap = 18;
        int yPos = 15;

        // Grupo Opcoes Gerais
        var grpOptions = new GroupBox
        {
            Text = "Opcoes Gerais",
            Location = new Point(margin, yPos),
            Size = new Size(groupWidth, 135)
        };

        _chkDryRun = new CheckBox
        {
            Text = "Modo Teste (Dry-Run) - Nao faz alteracoes reais",
            Location = new Point(15, 28),
            Size = new Size(500, 22),
            Checked = false,
            Font = new Font(Font, FontStyle.Bold)
        };
        _chkDryRun.CheckedChanged += ChkDryRun_Changed;

        _chkBlockBrowsers = new CheckBox
        {
            Text = "Bloquear instalacao de novos navegadores",
            Location = new Point(15, 55),
            Size = new Size(500, 22),
            Checked = true
        };
        _chkBlockBrowsers.CheckedChanged += ChkBlockBrowsers_Changed;

        _chkContentAnalysis = new CheckBox
        {
            Text = "Analise inteligente de conteudo (detecta sites adultos/distracao)",
            Location = new Point(15, 82),
            Size = new Size(500, 22),
            Checked = true
        };
        _chkContentAnalysis.CheckedChanged += ChkContentAnalysis_Changed;

        _chkStartup = new CheckBox
        {
            Text = "Iniciar Manager com o Windows",
            Location = new Point(15, 109),
            Size = new Size(500, 22),
            Checked = IsStartupEnabled()
        };
        _chkStartup.CheckedChanged += ChkStartup_Changed;

        grpOptions.Controls.Add(_chkDryRun);
        grpOptions.Controls.Add(_chkBlockBrowsers);
        grpOptions.Controls.Add(_chkContentAnalysis);
        grpOptions.Controls.Add(_chkStartup);

        yPos += grpOptions.Height + gap;

        // Grupo Analise de Conteudo
        var grpAnalysis = new GroupBox
        {
            Text = "Analise Inteligente - Sensibilidade",
            Location = new Point(margin, yPos),
            Size = new Size(groupWidth, 60)
        };

        var lblThreshold = new Label
        {
            Text = "Limite de bloqueio:",
            Location = new Point(15, 26),
            AutoSize = true
        };

        _numThreshold = new NumericUpDown
        {
            Location = new Point(135, 23),
            Size = new Size(60, 25),
            Minimum = 5,
            Maximum = 50,
            Value = 15,
            Increment = 5
        };
        _numThreshold.ValueChanged += NumThreshold_Changed;

        var lblThresholdHelp = new Label
        {
            Text = "(5 = muito rigoroso  |  15 = padrao  |  30 = permissivo)",
            Location = new Point(205, 26),
            AutoSize = true,
            ForeColor = Color.Gray
        };

        grpAnalysis.Controls.Add(lblThreshold);
        grpAnalysis.Controls.Add(_numThreshold);
        grpAnalysis.Controls.Add(lblThresholdHelp);

        yPos += grpAnalysis.Height + gap;

        // Grupo Analise por IA
        var grpAi = new GroupBox
        {
            Text = "Analise por IA (OpenAI)",
            Location = new Point(margin, yPos),
            Size = new Size(groupWidth, 100)
        };

        _chkUseAi = new CheckBox
        {
            Text = "Usar IA para classificar sites (substitui keywords/HTML)",
            Location = new Point(15, 28),
            Size = new Size(500, 22),
            Checked = false
        };
        _chkUseAi.CheckedChanged += ChkUseAi_Changed;

        var lblAiModel = new Label
        {
            Text = "Modelo:",
            Location = new Point(15, 63),
            AutoSize = true
        };

        _cboAiModel = new ComboBox
        {
            Location = new Point(75, 60),
            Size = new Size(155, 25),
            DropDownStyle = ComboBoxStyle.DropDown
        };
        _cboAiModel.Items.AddRange(["gpt-5.4-nano", "gpt-4o-mini", "gpt-4o", "gpt-4.1-nano"]);
        _cboAiModel.SelectedIndex = 0;
        _cboAiModel.TextChanged += CboAiModel_Changed;

        var lblAiKey = new Label
        {
            Text = "API Key:",
            Location = new Point(245, 63),
            AutoSize = true
        };

        _txtAiApiKey = new TextBox
        {
            Location = new Point(305, 60),
            Size = new Size(150, 25),
            UseSystemPasswordChar = true,
            PlaceholderText = "sk-..."
        };

        var btnSaveKey = new Button
        {
            Text = "Salvar",
            Location = new Point(462, 58),
            Size = new Size(55, 28)
        };
        btnSaveKey.Click += BtnSaveAiKey_Click;

        grpAi.Controls.Add(_chkUseAi);
        grpAi.Controls.Add(lblAiModel);
        grpAi.Controls.Add(_cboAiModel);
        grpAi.Controls.Add(lblAiKey);
        grpAi.Controls.Add(_txtAiApiKey);
        grpAi.Controls.Add(btnSaveKey);

        yPos += grpAi.Height + gap;

        // Grupo DNS
        var grpDns = new GroupBox
        {
            Text = "Configuracao de DNS",
            Location = new Point(margin, yPos),
            Size = new Size(groupWidth, 95)
        };

        var lblDns = new Label
        {
            Text = "DNS com Filtro:",
            Location = new Point(15, 28),
            AutoSize = true
        };

        _cboDns = new ComboBox
        {
            Location = new Point(15, 55),
            Size = new Size(410, 25),
            DropDownStyle = ComboBoxStyle.DropDownList
        };

        foreach (var provider in DnsProvider.AllowedProviders)
        {
            _cboDns.Items.Add($"{provider.Name} - {provider.Description}");
        }

        var btnApplyDns = new Button
        {
            Text = "Aplicar",
            Location = new Point(435, 53),
            Size = new Size(80, 28)
        };
        btnApplyDns.Click += BtnApplyDns_Click;

        grpDns.Controls.Add(lblDns);
        grpDns.Controls.Add(_cboDns);
        grpDns.Controls.Add(btnApplyDns);

        yPos += grpDns.Height + gap;

        // Grupo Sites Bloqueados
        var grpSites = new GroupBox
        {
            Text = "Sites Bloqueados",
            Location = new Point(margin, yPos),
            Size = new Size(groupWidth, 95)
        };

        _lblSiteCount = new Label
        {
            Text = "Sites bloqueados: 0",
            Location = new Point(15, 28),
            AutoSize = true
        };

        _txtSite = new TextBox
        {
            Location = new Point(15, 55),
            Size = new Size(310, 25),
            PlaceholderText = "Digite o site (ex: exemplo.com)"
        };

        var btnAddSite = new Button
        {
            Text = "Adicionar",
            Location = new Point(335, 53),
            Size = new Size(90, 28)
        };
        btnAddSite.Click += BtnAddSite_Click;

        var btnRemoveSite = new Button
        {
            Text = "Remover",
            Location = new Point(435, 53),
            Size = new Size(80, 28)
        };
        btnRemoveSite.Click += BtnRemoveSite_Click;

        grpSites.Controls.Add(_lblSiteCount);
        grpSites.Controls.Add(_txtSite);
        grpSites.Controls.Add(btnAddSite);
        grpSites.Controls.Add(btnRemoveSite);

        yPos += grpSites.Height + gap;

        // Status e Acoes do Servico
        var grpService = new GroupBox
        {
            Text = "Servico",
            Location = new Point(margin, yPos),
            Size = new Size(groupWidth, 65)
        };

        _lblServiceStatus = new Label
        {
            Text = "Status: Verificando...",
            Location = new Point(15, 28),
            AutoSize = true
        };

        var btnReinstallService = new Button
        {
            Text = "Reinstalar",
            Location = new Point(245, 24),
            Size = new Size(85, 28)
        };
        btnReinstallService.Click += BtnReinstallService_Click;

        var btnStartService = new Button
        {
            Text = "Iniciar",
            Location = new Point(340, 24),
            Size = new Size(85, 28)
        };
        btnStartService.Click += (s, e) => ControlService(true);

        var btnStopService = new Button
        {
            Text = "Parar",
            Location = new Point(435, 24),
            Size = new Size(80, 28)
        };
        btnStopService.Click += (s, e) => ControlService(false);

        grpService.Controls.Add(_lblServiceStatus);
        grpService.Controls.Add(btnReinstallService);
        grpService.Controls.Add(btnStartService);
        grpService.Controls.Add(btnStopService);

        yPos += grpService.Height + gap;

        // Log
        var grpLog = new GroupBox
        {
            Text = "Log",
            Location = new Point(margin, yPos),
            Size = new Size(groupWidth, 120)
        };

        _txtLog = new TextBox
        {
            Location = new Point(15, 24),
            Size = new Size(groupWidth - 30, 84),
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            Font = new Font("Consolas", 8.5f)
        };

        grpLog.Controls.Add(_txtLog);

        yPos += grpLog.Height + gap;

        // Botoes inferiores
        var btnPassword = new Button
        {
            Text = "Alterar Senha",
            Location = new Point(margin, yPos),
            Size = new Size(120, 34)
        };
        btnPassword.Click += BtnPassword_Click;

        var btnInstall = new Button
        {
            Text = "Instalar",
            Location = new Point(margin + 130, yPos),
            Size = new Size(90, 34)
        };
        btnInstall.Click += BtnInstall_Click;

        var btnMinimize = new Button
        {
            Text = "Minimizar",
            Location = new Point(margin + groupWidth - 220, yPos),
            Size = new Size(105, 34)
        };
        btnMinimize.Click += (s, e) => MinimizeToTray();

        var btnExit = new Button
        {
            Text = "Sair",
            Location = new Point(margin + groupWidth - 105, yPos),
            Size = new Size(105, 34)
        };
        btnExit.Click += (s, e) => ExitApplication();

        yPos += 50;

        // Define tamanho do form baseado no conteudo
        int formWidth = groupWidth + margin * 2 + 16; // 16 para bordas
        int formHeight = yPos + 20; // margem inferior extra
        Size = new Size(formWidth, formHeight);

        // Posiciona no canto inferior direito da tela
        var workingArea = Screen.PrimaryScreen!.WorkingArea;
        Location = new Point(
            workingArea.Right - Width - 10,
            workingArea.Bottom - Height - 10
        );

        Controls.Add(grpOptions);
        Controls.Add(grpAnalysis);
        Controls.Add(grpAi);
        Controls.Add(grpDns);
        Controls.Add(grpSites);
        Controls.Add(grpService);
        Controls.Add(grpLog);
        Controls.Add(btnPassword);
        Controls.Add(btnInstall);
        Controls.Add(btnMinimize);
        Controls.Add(btnExit);

        FormClosing += MainForm_FormClosing;
    }

    private void InitializeTrayIcon()
    {
        var contextMenu = new ContextMenuStrip();

        var showItem = new ToolStripMenuItem("Abrir");
        showItem.Click += (s, e) => ShowFromTray();
        showItem.Font = new Font(showItem.Font, FontStyle.Bold);

        var exitItem = new ToolStripMenuItem("Sair 🔒");
        exitItem.Click += (s, e) => ExitApplication();

        contextMenu.Items.Add(showItem);
        contextMenu.Items.Add(new ToolStripSeparator());
        contextMenu.Items.Add(exitItem);

        _trayIcon = new NotifyIcon
        {
            Text = "FocusGuard",
            Icon = SystemIcons.Shield,
            ContextMenuStrip = contextMenu,
            Visible = false
        };

        _trayIcon.DoubleClick += (s, e) => ShowFromTray();
    }

    private void MinimizeToTray()
    {
        Hide();
        _trayIcon.Visible = true;
        _trayIcon.ShowBalloonTip(2000, "FocusGuard", "Minimizado para a bandeja", ToolTipIcon.Info);
    }

    private void ShowFromTray()
    {
        Show();
        WindowState = FormWindowState.Normal;
        _trayIcon.Visible = false;
        Activate();
    }

    private void ExitApplication()
    {
        if (!RequirePassword()) return;

        _reallyClose = true;
        _trayIcon.Visible = false;
        _trayIcon.Dispose();
        Application.Exit();
    }

    private void Log(string message)
    {
        if (_txtLog.InvokeRequired)
        {
            _txtLog.Invoke(() => Log(message));
            return;
        }
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        _txtLog.AppendText($"[{timestamp}] {message}{Environment.NewLine}");
    }

    private void LoadConfig()
    {
        _config = AppConfig.Load();

        if (string.IsNullOrEmpty(_config.PasswordHash))
        {
            using var pwdForm = new PasswordForm(isSetup: true);
            if (pwdForm.ShowDialog() != DialogResult.OK || !pwdForm.Authenticated)
            {
                _reallyClose = true;
                Application.Exit();
                return;
            }
            _config = AppConfig.Load();
        }

        // Desabilita eventos para evitar disparo durante carregamento
        _chkDryRun.CheckedChanged -= ChkDryRun_Changed;
        _chkBlockBrowsers.CheckedChanged -= ChkBlockBrowsers_Changed;
        _chkContentAnalysis.CheckedChanged -= ChkContentAnalysis_Changed;
        _numThreshold.ValueChanged -= NumThreshold_Changed;
        _chkUseAi.CheckedChanged -= ChkUseAi_Changed;
        _cboAiModel.TextChanged -= CboAiModel_Changed;

        _cboDns.SelectedIndex = _config.SelectedDnsIndex;
        _chkDryRun.Checked = _config.DryRun;
        _chkBlockBrowsers.Checked = _config.BlockBrowserInstalls;
        _chkContentAnalysis.Checked = _config.ContentAnalysisEnabled;
        _numThreshold.Value = Math.Clamp(_config.ContentAnalysisThreshold, 5, 50);
        _chkUseAi.Checked = _config.UseAiAnalysis;
        _cboAiModel.Text = _config.AiModel;
        if (!string.IsNullOrEmpty(_config.AiApiKey))
            _txtAiApiKey.Text = _config.AiApiKey;

        // Reabilita eventos
        _chkDryRun.CheckedChanged += ChkDryRun_Changed;
        _chkBlockBrowsers.CheckedChanged += ChkBlockBrowsers_Changed;
        _chkContentAnalysis.CheckedChanged += ChkContentAnalysis_Changed;
        _numThreshold.ValueChanged += NumThreshold_Changed;
        _chkUseAi.CheckedChanged += ChkUseAi_Changed;
        _cboAiModel.TextChanged += CboAiModel_Changed;

        UpdateTitle();
        UpdateSiteCount();
        Log("Configuracao carregada");
    }

    private void UpdateTitle()
    {
        Text = _config.DryRun
            ? "FocusGuard - Gerenciador [MODO TESTE]"
            : "FocusGuard - Gerenciador";
    }

    private void UpdateSiteCount()
    {
        _lblSiteCount.Text = $"Sites bloqueados: {_config.BlockedSites.Count}";
    }

    private void ChkDryRun_Changed(object? sender, EventArgs e)
    {
        // Ativar DryRun = desativar protecao = requer senha
        if (_chkDryRun.Checked)
        {
            if (!RequirePassword())
            {
                _chkDryRun.Checked = false;
                return;
            }

            var result = MessageBox.Show(
                "Ativar modo teste desabilitara todas as protecoes.\nO sistema NAO fara alteracoes reais.\n\nTem certeza?",
                "Confirmar",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning
            );

            if (result != DialogResult.Yes)
            {
                _chkDryRun.Checked = false;
                return;
            }
        }

        _config.DryRun = _chkDryRun.Checked;
        _config.Save();
        UpdateTitle();
        Log($"Modo DryRun: {(_config.DryRun ? "ATIVADO" : "DESATIVADO")}");
    }

    private void ChkBlockBrowsers_Changed(object? sender, EventArgs e)
    {
        // Desativar bloqueio requer senha
        if (!_chkBlockBrowsers.Checked)
        {
            if (!RequirePassword())
            {
                _chkBlockBrowsers.Checked = true;
                return;
            }

            var result = MessageBox.Show(
                "Desativar o bloqueio permitira a instalacao de novos navegadores.\n\nTem certeza?",
                "Confirmar",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning
            );

            if (result != DialogResult.Yes)
            {
                _chkBlockBrowsers.Checked = true;
                return;
            }
        }

        _config.BlockBrowserInstalls = _chkBlockBrowsers.Checked;
        _config.Save();
        Log($"Bloqueio de navegadores: {(_config.BlockBrowserInstalls ? "ATIVADO" : "DESATIVADO")}");
    }

    private void ChkContentAnalysis_Changed(object? sender, EventArgs e)
    {
        // Desativar analise requer senha
        if (!_chkContentAnalysis.Checked)
        {
            if (!RequirePassword())
            {
                _chkContentAnalysis.Checked = true;
                return;
            }

            var result = MessageBox.Show(
                "Desativar a analise inteligente permitira acesso a sites adultos e de distracao.\n\nTem certeza?",
                "Confirmar",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning
            );

            if (result != DialogResult.Yes)
            {
                _chkContentAnalysis.Checked = true;
                return;
            }
        }

        _config.ContentAnalysisEnabled = _chkContentAnalysis.Checked;
        _config.Save();
        Log($"Analise de conteudo: {(_config.ContentAnalysisEnabled ? "ATIVADA" : "DESATIVADA")}");
    }

    private void NumThreshold_Changed(object? sender, EventArgs e)
    {
        _config.ContentAnalysisThreshold = (int)_numThreshold.Value;
        _config.Save();
        Log($"Sensibilidade alterada para: {_config.ContentAnalysisThreshold}");
    }

    private void ChkUseAi_Changed(object? sender, EventArgs e)
    {
        _config.UseAiAnalysis = _chkUseAi.Checked;
        _config.Save();
        Log($"Analise por IA: {(_config.UseAiAnalysis ? "ATIVADA" : "DESATIVADA")}");
    }

    private void CboAiModel_Changed(object? sender, EventArgs e)
    {
        var model = _cboAiModel.Text.Trim();
        if (!string.IsNullOrEmpty(model))
        {
            _config.AiModel = model;
            _config.Save();
        }
    }

    private void BtnSaveAiKey_Click(object? sender, EventArgs e)
    {
        var key = _txtAiApiKey.Text.Trim();
        if (string.IsNullOrEmpty(key))
        {
            MessageBox.Show("Digite a API key.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _config.SetAiApiKey(key);
        Log("API key salva no registro");
        MessageBox.Show("API key salva com sucesso.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private void UpdateServiceStatus()
    {
        try
        {
            using var sc = new ServiceController("FocusGuard Service");
            _lblServiceStatus.Text = $"Status: {sc.Status}";
            _lblServiceStatus.ForeColor = sc.Status == ServiceControllerStatus.Running ? Color.Green : Color.Red;
        }
        catch
        {
            _lblServiceStatus.Text = "Status: Nao instalado";
            _lblServiceStatus.ForeColor = Color.Orange;
        }
    }

    private void ControlService(bool start)
    {
        if (!start && !RequirePassword()) return;

        try
        {
            using var sc = new ServiceController("FocusGuard Service");
            if (start)
            {
                Log("Iniciando servico...");
                sc.Start();
                sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(10));
                Log("Servico iniciado");
            }
            else
            {
                Log("Parando servico...");
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(10));
                Log("Servico parado");
            }
            UpdateServiceStatus();
        }
        catch (Exception ex)
        {
            Log($"ERRO: {ex.Message}");
            MessageBox.Show($"Erro ao controlar servico: {ex.Message}", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private const string InstallPath = @"C:\Program Files\FocusGuard";

    private async void BtnInstall_Click(object? sender, EventArgs e)
    {
        Log("Iniciando instalacao...");

        try
        {
            // Encontra a raiz do projeto (onde esta o .sln)
            var managerDir = Path.GetDirectoryName(Application.ExecutablePath)!;
            var projectRoot = Path.GetFullPath(Path.Combine(managerDir, "..", "..", "..", ".."));
            var slnFile = Path.Combine(projectRoot, "FocusGuard.sln");

            if (!File.Exists(slnFile))
            {
                Log($"ERRO: FocusGuard.sln nao encontrado em {projectRoot}");
                MessageBox.Show("Raiz do projeto nao encontrada. Execute a partir do ambiente de dev.",
                    "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            Log($"Projeto: {projectRoot}");

            // 1. Para servico e mata processos
            Log("[1/5] Parando servico...");
            await RunScAsync("stop \"FocusGuard Service\"");
            await Task.Delay(2000);

            // Mata processos do servico (nao do Manager, que somos nos)
            foreach (var proc in Process.GetProcessesByName("FocusGuard.Service"))
            {
                try { proc.Kill(); proc.WaitForExit(3000); } catch { }
            }

            // 2. Publish
            Log("[2/5] Compilando (Release)...");
            var publishService = await RunProcessAsync("dotnet",
                $"publish \"{Path.Combine(projectRoot, "FocusGuard.Service")}\" -c Release -r win-x64 --self-contained true -o \"{Path.Combine(projectRoot, "publish", "service")}\"");
            if (publishService != 0) { Log("ERRO: Falha ao compilar Service"); return; }

            var publishManager = await RunProcessAsync("dotnet",
                $"publish \"{Path.Combine(projectRoot, "FocusGuard.Manager")}\" -c Release -r win-x64 --self-contained true -o \"{Path.Combine(projectRoot, "publish", "manager")}\"");
            if (publishManager != 0) { Log("ERRO: Falha ao compilar Manager"); return; }

            // 3. Copia arquivos
            Log("[3/5] Copiando para Program Files...");
            var serviceDest = Path.Combine(InstallPath, "Service");
            var managerDest = Path.Combine(InstallPath, "Manager");

            Directory.CreateDirectory(InstallPath);

            CopyDirectory(Path.Combine(projectRoot, "publish", "service"), serviceDest);
            CopyDirectory(Path.Combine(projectRoot, "publish", "manager"), managerDest);
            Log($"Copiado para {InstallPath}");

            // 4. Reinstala servico
            Log("[4/5] Reinstalando servico...");
            await RunScAsync("stop \"FocusGuard Service\"");
            await Task.Delay(2000);
            await RunScAsync("delete \"FocusGuard Service\"");
            await WaitForServiceDeletionAsync("FocusGuard Service");

            var serviceExe = Path.Combine(serviceDest, "FocusGuard.Service.exe");
            await RunScAsync($"create \"FocusGuard Service\" binPath=\"{serviceExe}\" start=auto DisplayName=\"FocusGuard Service\"");
            await RunScAsync("description \"FocusGuard Service\" \"Servico de protecao de foco e produtividade\"");
            await RunScAsync("failure \"FocusGuard Service\" reset= 86400 actions= restart/5000/restart/10000/restart/30000");

            // 5. Inicia
            Log("[5/5] Iniciando servico...");
            await RunScAsync("start \"FocusGuard Service\"");
            await Task.Delay(1000);

            UpdateServiceStatus();
            Log("Instalacao concluida!");
            MessageBox.Show($"FocusGuard instalado em:\n{InstallPath}\n\nServico iniciado.",
                "Instalacao", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            Log($"ERRO instalacao: {ex.Message}");
            MessageBox.Show($"Erro na instalacao: {ex.Message}", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private async Task<int> RunProcessAsync(string fileName, string arguments)
    {
        Log($"> {fileName} {arguments}");
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        process.Start();
        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        // Mostra so ultima linha relevante pra nao poluir
        var lastLine = output.Trim().Split('\n').LastOrDefault()?.Trim();
        if (!string.IsNullOrEmpty(lastLine))
            Log($"  {lastLine}");
        if (process.ExitCode != 0 && !string.IsNullOrWhiteSpace(error))
            Log($"  ERRO: {error.Trim().Split('\n').FirstOrDefault()}");

        return process.ExitCode;
    }

    private static void CopyDirectory(string source, string destination)
    {
        if (Directory.Exists(destination))
            Directory.Delete(destination, true);

        Directory.CreateDirectory(destination);

        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(source, file);
            var destFile = Path.Combine(destination, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(destFile)!);
            File.Copy(file, destFile, true);
        }
    }

    private async void BtnReinstallService_Click(object? sender, EventArgs e)
    {
        Log("Reinstalando servico...");

        try
        {
            // Resolve o caminho do executavel do servico
            // 1. Instalado: mesmo diretorio do Manager
            var managerDir = Path.GetDirectoryName(Application.ExecutablePath)!;
            var serviceExe = Path.Combine(managerDir, "FocusGuard.Service.exe");

            // 2. Fallback dev: bin do projeto
            if (!File.Exists(serviceExe))
                serviceExe = Path.Combine(managerDir, "..", "..", "..", "..", "FocusGuard.Service", "bin", "Debug", "net9.0-windows", "win-x64", "FocusGuard.Service.exe");
            if (!File.Exists(serviceExe))
                serviceExe = Path.Combine(managerDir, "..", "..", "..", "..", "FocusGuard.Service", "bin", "Debug", "net9.0-windows", "FocusGuard.Service.exe");

            if (!File.Exists(serviceExe))
            {
                Log("ERRO: FocusGuard.Service.exe nao encontrado");
                MessageBox.Show("Executavel do servico nao encontrado.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            serviceExe = Path.GetFullPath(serviceExe);
            Log($"Executavel: {serviceExe}");

            // 1. Para e remove o servico existente
            await RunScAsync($"stop \"FocusGuard Service\"");
            await Task.Delay(2000);
            await RunScAsync($"delete \"FocusGuard Service\"");
            await WaitForServiceDeletionAsync("FocusGuard Service");

            // 2. Cria novamente
            var createResult = await RunScAsync(
                $"create \"FocusGuard Service\" binPath=\"{serviceExe}\" start=auto DisplayName=\"FocusGuard Service\"");

            if (createResult != 0)
            {
                Log("ERRO: Falha ao criar servico");
                return;
            }

            await RunScAsync($"description \"FocusGuard Service\" \"Servico de protecao de foco e produtividade\"");

            // 3. Inicia
            var startResult = await RunScAsync($"start \"FocusGuard Service\"");
            await Task.Delay(1000);

            UpdateServiceStatus();
            Log(startResult == 0 ? "Servico reinstalado e iniciado!" : "Servico criado, mas falha ao iniciar");
        }
        catch (Exception ex)
        {
            Log($"ERRO reinstalacao: {ex.Message}");
        }
    }

    private async Task<int> RunScAsync(string arguments)
    {
        Log($"sc.exe {arguments}");
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        process.Start();
        var output = await process.StandardOutput.ReadToEndAsync();
        var error = await process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();

        if (!string.IsNullOrWhiteSpace(output))
            Log(output.Trim());
        if (!string.IsNullOrWhiteSpace(error))
            Log($"ERRO: {error.Trim()}");

        return process.ExitCode;
    }

    /// <summary>
    /// Aguarda ate o servico ser completamente removido pelo Windows (polling sc query).
    /// sc delete marca para exclusao, mas so remove de fato quando o processo encerra.
    /// </summary>
    private async Task WaitForServiceDeletionAsync(string serviceName, int timeoutMs = 15000)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            await Task.Delay(500);
            var result = await RunScAsync($"query \"{serviceName}\"");
            // sc query retorna != 0 quando o servico nao existe mais
            if (result != 0)
            {
                Log("Servico removido com sucesso");
                return;
            }
        }
        Log("AVISO: Timeout aguardando remocao do servico. Tentando criar mesmo assim...");
    }

    private void BtnApplyDns_Click(object? sender, EventArgs e)
    {
        _config.SelectedDnsIndex = _cboDns.SelectedIndex;
        _config.Save();

        var dns = _config.GetSelectedDns();
        var adapters = DnsService.GetActiveNetworkAdapters();

        Log($"Aplicando DNS: {dns.Name}");

        foreach (var adapter in adapters)
        {
            DnsService.SetDnsForProxy(adapter, dns, _config.DryRun, Log);
        }

        var msg = _config.DryRun
            ? $"[DRY-RUN] DNS seria alterado para {dns.Name}"
            : $"DNS alterado para {dns.Name}";

        Log(msg);
        MessageBox.Show(msg, "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private string NormalizeSite(string site)
    {
        return site.Trim().ToLower()
            .Replace("https://", "")
            .Replace("http://", "")
            .Replace("www.", "")
            .TrimEnd('/');
    }

    private void BtnAddSite_Click(object? sender, EventArgs e)
    {
        var site = NormalizeSite(_txtSite.Text);
        if (string.IsNullOrEmpty(site))
        {
            MessageBox.Show("Digite um site.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (_config.BlockedSites.Contains(site, StringComparer.OrdinalIgnoreCase))
        {
            MessageBox.Show("Site ja esta bloqueado.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _config.BlockedSites.Add(site);
        _config.Save();

        HostsService.AddBlockedSites([site], _config.DryRun, Log);

        Log($"{(_config.DryRun ? "[DRY-RUN] " : "")}Site adicionado: {site}");
        UpdateSiteCount();
        _txtSite.Clear();
    }

    private void BtnRemoveSite_Click(object? sender, EventArgs e)
    {
        if (!RequirePassword()) return;

        var site = NormalizeSite(_txtSite.Text);
        if (string.IsNullOrEmpty(site))
        {
            MessageBox.Show("Digite o site a remover.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var existing = _config.BlockedSites.FirstOrDefault(s => s.Equals(site, StringComparison.OrdinalIgnoreCase));
        if (existing == null)
        {
            MessageBox.Show("Site nao esta na lista de bloqueados.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _config.BlockedSites.Remove(existing);
        _config.Save();

        HostsService.RemoveBlockedSite(existing, _config.DryRun, Log);

        Log($"{(_config.DryRun ? "[DRY-RUN] " : "")}Site removido: {existing}");
        UpdateSiteCount();
        _txtSite.Clear();
    }

    private void BtnPassword_Click(object? sender, EventArgs e)
    {
        if (!RequirePassword()) return;

        using var pwdForm = new PasswordForm(isSetup: true);
        pwdForm.ShowDialog();
        _config = AppConfig.Load();
        Log("Senha alterada");
    }

    private void MainForm_FormClosing(object? sender, FormClosingEventArgs e)
    {
        if (_reallyClose) return;

        e.Cancel = true;
        MinimizeToTray();
    }

    private bool RequirePassword()
    {
        using var pwdForm = new PasswordForm();
        return pwdForm.ShowDialog() == DialogResult.OK && pwdForm.Authenticated;
    }

    private const string StartupRegistryKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string StartupValueName = "FocusGuardManager";

    private bool IsStartupEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(StartupRegistryKey);
            return key?.GetValue(StartupValueName) != null;
        }
        catch
        {
            return false;
        }
    }

    private void ChkStartup_Changed(object? sender, EventArgs e)
    {
        try
        {
            SetStartup(_chkStartup.Checked);
            Log($"Iniciar com Windows: {(_chkStartup.Checked ? "ATIVADO" : "DESATIVADO")}");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao configurar inicializacao: {ex.Message}", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
            _chkStartup.Checked = !_chkStartup.Checked; // Reverte
        }
    }

    private void SetStartup(bool enable)
    {
        using var key = Registry.CurrentUser.OpenSubKey(StartupRegistryKey, true);
        if (key == null)
            throw new Exception("Nao foi possivel abrir registro de inicializacao");

        if (enable)
        {
            var exePath = Application.ExecutablePath;
            key.SetValue(StartupValueName, $"\"{exePath}\" --minimized", RegistryValueKind.String);
        }
        else
        {
            key.DeleteValue(StartupValueName, false);
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _trayIcon?.Dispose();
        }
        base.Dispose(disposing);
    }
}
