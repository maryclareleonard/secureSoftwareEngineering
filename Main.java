
import com.ibm.wala.ipa.callgraph.*;
import com.ibm.wala.ipa.callgraph.cha.CHACallGraph;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.IClassHierarchy;
import com.ibm.wala.ssa.IR;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.util.config.AnalysisScopeReader;
import com.ibm.wala.util.io.FileProvider;

public class Main {

    static int countOfNodes = 0; //for 2a
    static int countOfEdges = 0; //for 2b
   public static void main(String[] args) {
    File exFile = new FileProvider().getFile("Sample.jar");
    
    URL resource = LiveExampleL14.class.getResource("Example1.jar");
    AnalysisScope scope = AnalysisScopeReader.makeJavaBinaryAnalysisScope(resource.getPath(),exFile );
    String runtimeClasses = LiveExampleL14.class.getResource("jdk-17.0.1/rt.jar").getPath();
    AnalysisScopeReader.addClassPathToScope(runtimeClasses, scope, ClassLoaderReference.Primordial);

    //Create Class Hierarchy for Sample.jar file
    IClassHierarchy classHierarchy = ClassHierarchyFactory.make(scope);

    // n-CFA graph
    AnalysisOptions options = new AnalysisOptions();
    options.setEntrypoints(Util.makeMainEntrypoints(scope, classHierarchy));
    SSAPropagationCallGraphBuilder builder = Util.makeNCFABuilder(1, options, new AnalysisCacheImpl(), classHierarchy, scope);
    CallGraph callGraph = builder.makeCallGraph(options);

    System.out.println("# Nodes " + callGraph.getNumberOfNodes());
    System.out.println("# Edges " + callGraph.getNumberOfEdges()); 
    PointerAnalysis<InstanceKey> pa = builder.getPointerAnalysis();
    SDG sdg = new SDG(callGraph, pa, Slicer.DataDependenceOptions.NO_BASE_NO_HEAP, Slicer.ControlDependenceOptions.FULL);
    System.out.println(sdg.getNumberOfNodes());

    //Taint Analyzer
    Set<Statement> sinks = findSinks(sdg);
    Set<Statement> sources = findSources(sdg);

    Set<List<Statement>> vulnerablePaths = getVulnerablePaths(sdg, sources, sinks);

    for (List<Statement> path : vulnerablePaths) {
        System.out.println("VULNERABLE PATH");
        for (Statement statement : path) {

            if (statement.getKind() == Statement.Kind.NORMAL) {
                System.out.println("\t" + ((NormalStatement) statement).getInstruction());
                int instructionIndex = ((NormalStatement) statement).getInstructionIndex();
                int lineNum = ((ShrikeCTMethod) statement.getNode().getMethod()).getLineNumber(instructionIndex);
                System.out.println("Source line number = " + lineNum );
            }
        }
        System.out.println("------------------------------");
    }


    }
}
