using FocusGuard.Shared.Models;

namespace FocusGuard.Manager;

public partial class PasswordForm : Form
{
    private readonly bool _isSetup;
    private readonly AppConfig _config;
    private readonly string _challengePhrase;

    private static readonly string[] ProductivityPhrases =
    [
        "Eu escolho focar no que realmente importa para o meu crescimento pessoal e profissional, deixando distrações de lado. Cada minuto investido em trabalho significativo me aproxima dos meus objetivos, enquanto cada distração me afasta do sucesso que sei que posso alcançar.",
        "Meu tempo é valioso demais para ser desperdiçado com conteúdo que não agrega valor à minha vida ou aos meus objetivos. Reconheço que cada hora perdida é uma oportunidade que nunca mais voltará, e escolho honrar meu potencial usando meu tempo com sabedoria e propósito.",
        "Cada momento de foco é um investimento no meu futuro. Escolho construir algo significativo em vez de me distrair. A pessoa que serei daqui a um ano está sendo moldada pelas decisões que tomo hoje, e decido que essa pessoa será alguém de quem terei orgulho.",
        "A disciplina que pratico agora define a pessoa que serei amanhã. Mantenho meu compromisso com a produtividade porque sei que o sucesso não é um evento, mas sim o resultado de escolhas consistentes feitas dia após dia, momento após momento, mesmo quando ninguém está olhando.",
        "Reconheço que buscar distrações é fugir dos desafios. Escolho enfrentar minhas responsabilidades com coragem e determinação. A dor temporária do esforço é infinitamente menor que a dor permanente do arrependimento por não ter tentado dar o meu melhor quando tive a chance.",
        "O sucesso é construído através de pequenas escolhas consistentes. Esta é mais uma escolha que define meu caráter. Cada vez que resisto à tentação de me distrair, estou fortalecendo os músculos da disciplina que me carregarão em direção aos meus maiores sonhos e aspirações.",
        "Ao resistir às distrações, fortaleço minha capacidade de autocontrole e me aproximo dos meus sonhos. A verdadeira força não está em nunca sentir vontade de procrastinar, mas em reconhecer essa vontade e escolher conscientemente um caminho melhor para minha vida.",
        "Minha mente merece conteúdo que a eleve, não que a entorpeça. Escolho alimentar meu intelecto com sabedoria e conhecimento que me transformem em uma pessoa melhor. O que consumo mentalmente molda quem eu sou, e escolho ser alguém extraordinário através das minhas escolhas diárias.",
        "Cada vez que venço a tentação de procrastinar, provo a mim mesmo que sou mais forte do que meus impulsos momentâneos. Essa vitória silenciosa constrói a autoconfiança genuína que vem de saber que posso contar comigo mesmo quando as coisas ficam difíceis.",
        "O arrependimento de perder tempo é maior do que o esforço de manter o foco. Escolho não me arrepender no futuro por decisões tomadas hoje. Daqui a cinco anos, olharei para trás e agradecerei a mim mesmo por ter permanecido firme neste momento de tentação.",
        "Estou construindo hábitos que me levarão ao sucesso. Desativar esta proteção vai contra tudo que busco alcançar na minha vida. Lembro-me de por que comecei esta jornada e renovo meu compromisso com a versão mais produtiva e realizada de mim mesmo que desejo me tornar.",
        "As pessoas que admiro não chegaram onde estão cedendo a distrações. Sigo o exemplo daqueles que me inspiram a ser melhor. Sei que o caminho para a grandeza é pavimentado com incontáveis momentos de escolher o difícil sobre o fácil, o importante sobre o urgente.",
        "Meu eu do futuro me agradecerá por manter o foco agora. Não vou decepcionar quem estarei me tornando através das minhas escolhas. Cada decisão de permanecer focado é um presente que dou para a pessoa que serei amanhã, no próximo mês e nos próximos anos.",
        "A liberdade verdadeira está em ter controle sobre minhas próprias escolhas, não em ceder a impulsos momentâneos que me escravizam. Escolho a liberdade de longo prazo que vem da disciplina sobre a falsa liberdade de curto prazo que vem de ceder a cada desejo passageiro.",
        "Reconheço que configurei esta proteção por boas razões. Meu eu do passado sabia o que era melhor para mim e tomou essa decisão com clareza. Honro essa sabedoria anterior mantendo meu compromisso, mesmo quando a tentação tenta me convencer do contrário neste momento."
    ];

    public bool Authenticated { get; private set; }

    public PasswordForm(bool isSetup = false)
    {
        _isSetup = isSetup;
        _config = AppConfig.Load();
        _challengePhrase = ProductivityPhrases[Random.Shared.Next(ProductivityPhrases.Length)];

        InitializeComponent();
    }

    private void InitializeComponent()
    {
        Text = _isSetup ? "Definir Senha" : "Confirmação de Segurança";
        ClientSize = new Size(_isSetup ? 320 : 550, _isSetup ? 160 : 320);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterScreen;
        MaximizeBox = false;
        MinimizeBox = false;

        int yPos = 15;

        var lblPassword = new Label
        {
            Text = _isSetup ? "Nova Senha:" : "Senha:",
            Location = new Point(15, yPos),
            AutoSize = true
        };
        yPos += 20;

        var txtPassword = new TextBox
        {
            Location = new Point(15, yPos),
            Size = new Size(_isSetup ? 290 : 520, 25),
            UseSystemPasswordChar = true,
            Name = "txtPassword"
        };
        yPos += 35;

        Label? lblConfirm = null;
        TextBox? txtConfirm = null;
        Label? lblChallengeTitle = null;
        Label? lblChallengePhrase = null;
        Label? lblChallengeInput = null;
        TextBox? txtChallenge = null;

        if (_isSetup)
        {
            lblConfirm = new Label
            {
                Text = "Confirmar:",
                Location = new Point(15, yPos),
                AutoSize = true
            };
            yPos += 20;

            txtConfirm = new TextBox
            {
                Location = new Point(15, yPos),
                Size = new Size(290, 25),
                UseSystemPasswordChar = true,
                Name = "txtConfirm"
            };
            yPos += 35;
        }
        else
        {
            // Frase de desafio para modo de validação
            lblChallengeTitle = new Label
            {
                Text = "Para continuar, redigite a frase abaixo:",
                Location = new Point(15, yPos),
                AutoSize = true,
                Font = new Font(Font, FontStyle.Bold)
            };
            yPos += 25;

            lblChallengePhrase = new Label
            {
                Text = $"\"{_challengePhrase}\"",
                Location = new Point(15, yPos),
                Size = new Size(520, 80),
                Font = new Font("Segoe UI", 9.5f, FontStyle.Italic),
                ForeColor = Color.DarkBlue,
                BorderStyle = BorderStyle.FixedSingle,
                BackColor = Color.FromArgb(240, 248, 255),
                Padding = new Padding(8),
                TextAlign = ContentAlignment.MiddleCenter
            };
            yPos += 90;

            lblChallengeInput = new Label
            {
                Text = "Digite a frase exatamente como aparece acima:",
                Location = new Point(15, yPos),
                AutoSize = true
            };
            yPos += 22;

            txtChallenge = new TextBox
            {
                Location = new Point(15, yPos),
                Size = new Size(520, 60),
                Multiline = true,
                Name = "txtChallenge",
                Font = new Font("Segoe UI", 9f)
            };
            yPos += 70;
        }

        var btnOk = new Button
        {
            Text = "OK",
            DialogResult = DialogResult.OK,
            Location = new Point(_isSetup ? 140 : 360, yPos),
            Size = new Size(80, 28)
        };

        var btnCancel = new Button
        {
            Text = "Cancelar",
            DialogResult = DialogResult.Cancel,
            Location = new Point(_isSetup ? 225 : 450, yPos),
            Size = new Size(80, 28)
        };

        btnOk.Click += (s, e) =>
        {
            if (_isSetup)
            {
                if (string.IsNullOrEmpty(txtPassword.Text))
                {
                    MessageBox.Show("Digite uma senha.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    DialogResult = DialogResult.None;
                    return;
                }

                if (txtPassword.Text != txtConfirm!.Text)
                {
                    MessageBox.Show("As senhas não conferem.", "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    DialogResult = DialogResult.None;
                    return;
                }

                _config.SetPassword(txtPassword.Text);
                _config.Save();
                Authenticated = true;
            }
            else
            {
                // Validar senha
                if (!_config.ValidatePassword(txtPassword.Text))
                {
                    MessageBox.Show("Senha incorreta.", "Erro", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    DialogResult = DialogResult.None;
                    txtPassword.Clear();
                    txtPassword.Focus();
                    return;
                }

                // Validar frase de desafio
                var typedPhrase = txtChallenge!.Text.Trim();
                if (!string.Equals(typedPhrase, _challengePhrase, StringComparison.Ordinal))
                {
                    MessageBox.Show(
                        "A frase digitada não confere.\n\nDigite exatamente como aparece, incluindo pontuação.",
                        "Frase Incorreta",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    DialogResult = DialogResult.None;
                    txtChallenge.Focus();
                    txtChallenge.SelectAll();
                    return;
                }

                Authenticated = true;
            }
        };

        Controls.Add(lblPassword);
        Controls.Add(txtPassword);
        if (_isSetup)
        {
            Controls.Add(lblConfirm!);
            Controls.Add(txtConfirm!);
        }
        else
        {
            Controls.Add(lblChallengeTitle!);
            Controls.Add(lblChallengePhrase!);
            Controls.Add(lblChallengeInput!);
            Controls.Add(txtChallenge!);
        }
        Controls.Add(btnOk);
        Controls.Add(btnCancel);

        AcceptButton = btnOk;
        CancelButton = btnCancel;

        ActiveControl = txtPassword;
    }
}
