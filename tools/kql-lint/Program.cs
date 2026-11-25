using Kusto.Language;

if (args.Length == 0)
{
    Console.Error.WriteLine("Uso: kql-lint <arquivo.kql | diretorio>...");
    return 1;
}

var files = new List<string>();
foreach (var arg in args)
{
    if (Directory.Exists(arg))
    {
        files.AddRange(Directory.EnumerateFiles(arg, "*.kql", SearchOption.AllDirectories));
    }
    else if (File.Exists(arg))
    {
        files.Add(arg);
    }
    else
    {
        Console.Error.WriteLine($"Caminho nao encontrado: {arg}");
        return 1;
    }
}

files.Sort(StringComparer.Ordinal);
if (files.Count == 0)
{
    Console.Error.WriteLine("Nenhum arquivo .kql para analisar.");
    return 1;
}

var failed = false;
foreach (var path in files)
{
    var text = File.ReadAllText(path);
    var code = KustoCode.Parse(text);
    foreach (var diagnostic in code.GetDiagnostics())
    {
        if (diagnostic.Severity != DiagnosticSeverity.Error)
        {
            continue;
        }

        failed = true;
        Console.Error.WriteLine($"{path}:{diagnostic.Start}: {diagnostic.Message}");
    }
}

if (failed)
{
    return 1;
}

Console.WriteLine($"KQL sem erros de sintaxe: {files.Count} arquivo(s).");
return 0;
