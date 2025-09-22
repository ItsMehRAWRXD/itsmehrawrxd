"""
Agentic Framework - Main Orchestrator
A sophisticated agent system using LangGraph for stateful, multi-step reasoning
"""

from langgraph.graph import StateGraph, END
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage
from typing import List, Dict, Any, Optional, TypedDict
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AgentState(TypedDict):
    """State management for the agent"""
    messages: List[BaseMessage]
    current_tool: Optional[str]
    tool_results: List[Dict[str, Any]]
    reasoning_steps: List[str]
    final_response: Optional[str]
    error_count: int
    max_iterations: int
    current_iteration: int

class AgentOrchestrator:
    """Main orchestrator for the agentic framework"""
    
    def __init__(self, llm_client, tools: Dict[str, Any], max_iterations: int = 10):
        self.llm_client = llm_client
        self.tools = tools
        self.max_iterations = max_iterations
        self.graph = self._build_graph()
        
    def _build_graph(self) -> StateGraph:
        """Build the LangGraph workflow"""
        graph_builder = StateGraph(AgentState)
        
        # Add nodes
        graph_builder.add_node("reasoning_node", self._reasoning_node)
        graph_builder.add_node("tool_selection_node", self._tool_selection_node)
        graph_builder.add_node("tool_execution_node", self._tool_execution_node)
        graph_builder.add_node("response_synthesis_node", self._response_synthesis_node)
        graph_builder.add_node("error_handling_node", self._error_handling_node)
        
        # Add edges
        graph_builder.add_conditional_edges(
            "reasoning_node",
            self._route_after_reasoning,
            {
                "tool_needed": "tool_selection_node",
                "direct_response": "response_synthesis_node",
                "error": "error_handling_node"
            }
        )
        
        graph_builder.add_edge("tool_selection_node", "tool_execution_node")
        graph_builder.add_edge("tool_execution_node", "reasoning_node")
        graph_builder.add_edge("response_synthesis_node", END)
        graph_builder.add_edge("error_handling_node", END)
        
        # Set entry point
        graph_builder.set_entry_point("reasoning_node")
        
        return graph_builder.compile()
    
    def _reasoning_node(self, state: AgentState) -> AgentState:
        """Main reasoning node - analyzes the current state and decides next action"""
        try:
            current_iteration = state.get("current_iteration", 0) + 1
            state["current_iteration"] = current_iteration
            
            # Check if we've exceeded max iterations
            if current_iteration > state.get("max_iterations", self.max_iterations):
                state["final_response"] = "I've reached the maximum number of reasoning iterations. Let me provide a response based on what I've gathered so far."
                return state
            
            # Get the latest message
            last_message = state["messages"][-1] if state["messages"] else None
            if not last_message:
                state["final_response"] = "No message to process."
                return state
            
            # Create reasoning prompt
            reasoning_prompt = self._create_reasoning_prompt(state, last_message)
            
            # Get LLM reasoning
            reasoning_response = self.llm_client.generate(
                prompt=reasoning_prompt,
                temperature=0.1,  # Low temperature for consistent reasoning
                max_tokens=500
            )
            
            # Parse reasoning response
            reasoning_steps = state.get("reasoning_steps", [])
            reasoning_steps.append(f"Iteration {current_iteration}: {reasoning_response}")
            state["reasoning_steps"] = reasoning_steps
            
            # Determine if tools are needed
            if self._needs_tool(reasoning_response):
                state["current_tool"] = self._extract_tool_name(reasoning_response)
                logger.info(f"Tool needed: {state['current_tool']}")
            else:
                state["current_tool"] = None
                logger.info("Direct response possible")
            
            return state
            
        except Exception as e:
            logger.error(f"Error in reasoning node: {str(e)}")
            state["error_count"] = state.get("error_count", 0) + 1
            return state
    
    def _tool_selection_node(self, state: AgentState) -> AgentState:
        """Selects and prepares the appropriate tool"""
        try:
            tool_name = state.get("current_tool")
            if not tool_name or tool_name not in self.tools:
                state["final_response"] = f"Tool '{tool_name}' not available."
                return state
            
            # Prepare tool parameters
            last_message = state["messages"][-1]
            tool_params = self._extract_tool_parameters(last_message.content, tool_name)
            state["tool_params"] = tool_params
            
            logger.info(f"Selected tool: {tool_name} with params: {tool_params}")
            return state
            
        except Exception as e:
            logger.error(f"Error in tool selection: {str(e)}")
            state["error_count"] = state.get("error_count", 0) + 1
            return state
    
    def _tool_execution_node(self, state: AgentState) -> AgentState:
        """Executes the selected tool"""
        try:
            tool_name = state.get("current_tool")
            tool_params = state.get("tool_params", {})
            
            if tool_name not in self.tools:
                state["final_response"] = f"Tool '{tool_name}' not found."
                return state
            
            # Execute the tool
            tool = self.tools[tool_name]
            tool_result = tool.execute(**tool_params)
            
            # Store tool result
            tool_results = state.get("tool_results", [])
            tool_results.append({
                "tool": tool_name,
                "params": tool_params,
                "result": tool_result,
                "timestamp": datetime.now().isoformat()
            })
            state["tool_results"] = tool_results
            
            # Add tool result as a message for next iteration
            tool_message = AIMessage(content=f"Tool '{tool_name}' result: {tool_result}")
            state["messages"].append(tool_message)
            
            logger.info(f"Executed tool: {tool_name}")
            return state
            
        except Exception as e:
            logger.error(f"Error in tool execution: {str(e)}")
            state["error_count"] = state.get("error_count", 0) + 1
            return state
    
    def _response_synthesis_node(self, state: AgentState) -> AgentState:
        """Synthesizes the final response"""
        try:
            # Create synthesis prompt
            synthesis_prompt = self._create_synthesis_prompt(state)
            
            # Generate final response
            final_response = self.llm_client.generate(
                prompt=synthesis_prompt,
                temperature=0.7,  # Higher temperature for creative synthesis
                max_tokens=1000
            )
            
            state["final_response"] = final_response
            logger.info("Generated final response")
            return state
            
        except Exception as e:
            logger.error(f"Error in response synthesis: {str(e)}")
            state["final_response"] = f"Error generating response: {str(e)}"
            return state
    
    def _error_handling_node(self, state: AgentState) -> AgentState:
        """Handles errors and provides fallback response"""
        error_count = state.get("error_count", 0)
        
        if error_count >= 3:
            state["final_response"] = "I encountered multiple errors and cannot provide a reliable response at this time."
        else:
            state["final_response"] = "I encountered an error while processing your request. Please try rephrasing your question."
        
        logger.warning(f"Error handling activated. Error count: {error_count}")
        return state
    
    def _route_after_reasoning(self, state: AgentState) -> str:
        """Routes to the next node after reasoning"""
        if state.get("error_count", 0) > 0:
            return "error"
        elif state.get("current_tool"):
            return "tool_needed"
        else:
            return "direct_response"
    
    def _create_reasoning_prompt(self, state: AgentState, last_message: BaseMessage) -> str:
        """Creates a prompt for the reasoning node"""
        available_tools = list(self.tools.keys())
        tool_results = state.get("tool_results", [])
        
        prompt = f"""
You are an AI assistant with access to various tools. Analyze the current situation and decide what to do next.

Available tools: {', '.join(available_tools)}

Current conversation:
{self._format_messages(state['messages'])}

Previous tool results:
{self._format_tool_results(tool_results)}

Current iteration: {state.get('current_iteration', 1)}/{state.get('max_iterations', self.max_iterations)}

Instructions:
1. Analyze the user's request and current context
2. Determine if you need to use a tool or can respond directly
3. If you need a tool, specify which one and why
4. If you can respond directly, explain your reasoning

Respond in this format:
REASONING: [Your analysis and reasoning]
ACTION: [tool_name or direct_response]
TOOL_PARAMS: [if using a tool, specify parameters as JSON]
"""
        return prompt
    
    def _create_synthesis_prompt(self, state: AgentState) -> str:
        """Creates a prompt for response synthesis"""
        tool_results = state.get("tool_results", [])
        reasoning_steps = state.get("reasoning_steps", [])
        
        prompt = f"""
Based on the following information, provide a comprehensive and helpful response to the user.

Reasoning steps:
{chr(10).join(reasoning_steps)}

Tool results:
{self._format_tool_results(tool_results)}

Original request:
{state['messages'][0].content if state['messages'] else 'No request'}

Provide a clear, accurate, and helpful response that incorporates all relevant information gathered.
"""
        return prompt
    
    def _needs_tool(self, reasoning_response: str) -> bool:
        """Determines if a tool is needed based on reasoning response"""
        return "ACTION: tool" in reasoning_response or "tool_name" in reasoning_response.lower()
    
    def _extract_tool_name(self, reasoning_response: str) -> Optional[str]:
        """Extracts tool name from reasoning response"""
        lines = reasoning_response.split('\n')
        for line in lines:
            if line.startswith('ACTION:') and 'tool' in line.lower():
                # Extract tool name from the line
                parts = line.split(':')
                if len(parts) > 1:
                    tool_part = parts[1].strip()
                    # Look for tool names in the available tools
                    for tool_name in self.tools.keys():
                        if tool_name.lower() in tool_part.lower():
                            return tool_name
        return None
    
    def _extract_tool_parameters(self, message_content: str, tool_name: str) -> Dict[str, Any]:
        """Extracts parameters for tool execution"""
        # This is a simplified implementation
        # In a real system, you'd use more sophisticated parameter extraction
        return {
            "query": message_content,
            "context": "user_request"
        }
    
    def _format_messages(self, messages: List[BaseMessage]) -> str:
        """Formats messages for display"""
        formatted = []
        for msg in messages:
            if isinstance(msg, HumanMessage):
                formatted.append(f"User: {msg.content}")
            elif isinstance(msg, AIMessage):
                formatted.append(f"Assistant: {msg.content}")
            elif isinstance(msg, SystemMessage):
                formatted.append(f"System: {msg.content}")
        return '\n'.join(formatted)
    
    def _format_tool_results(self, tool_results: List[Dict[str, Any]]) -> str:
        """Formats tool results for display"""
        if not tool_results:
            return "No tool results yet."
        
        formatted = []
        for result in tool_results:
            formatted.append(f"Tool: {result['tool']}")
            formatted.append(f"Result: {result['result']}")
            formatted.append("---")
        
        return '\n'.join(formatted)
    
    def process_request(self, user_input: str) -> Dict[str, Any]:
        """Main entry point for processing user requests"""
        try:
            # Initialize state
            initial_state = AgentState(
                messages=[HumanMessage(content=user_input)],
                current_tool=None,
                tool_results=[],
                reasoning_steps=[],
                final_response=None,
                error_count=0,
                max_iterations=self.max_iterations,
                current_iteration=0
            )
            
            # Run the graph
            final_state = self.graph.invoke(initial_state)
            
            return {
                "response": final_state.get("final_response", "No response generated"),
                "reasoning_steps": final_state.get("reasoning_steps", []),
                "tool_results": final_state.get("tool_results", []),
                "iterations": final_state.get("current_iteration", 0),
                "success": final_state.get("error_count", 0) == 0
            }
            
        except Exception as e:
            logger.error(f"Error processing request: {str(e)}")
            return {
                "response": f"Error processing request: {str(e)}",
                "reasoning_steps": [],
                "tool_results": [],
                "iterations": 0,
                "success": False
            }

# Example usage
if __name__ == "__main__":
    # This would be replaced with your actual LLM client
    class MockLLMClient:
        def generate(self, prompt: str, temperature: float = 0.7, max_tokens: int = 500) -> str:
            return f"Mock response to: {prompt[:50]}..."
    
    # Mock tools
    class MockTool:
        def __init__(self, name: str):
            self.name = name
        
        def execute(self, **kwargs) -> str:
            return f"Mock result from {self.name} with params: {kwargs}"
    
    # Initialize the orchestrator
    llm_client = MockLLMClient()
    tools = {
        "file_search": MockTool("file_search"),
        "web_search": MockTool("web_search"),
        "code_analysis": MockTool("code_analysis")
    }
    
    orchestrator = AgentOrchestrator(llm_client, tools)
    
    # Test the system
    result = orchestrator.process_request("Search for Python web frameworks and analyze the results")
    print(json.dumps(result, indent=2))
