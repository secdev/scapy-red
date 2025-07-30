
# Completion for {script_name}
_scapyred_complete_{script_name}() {{
  completions=({all_completion_arguments})
  noarguments=({noarguments_completion_arguments})

  _scapyred_complete
}}
complete -F _scapyred_complete_{script_name} {script_name}
