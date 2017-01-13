	function updateActionTable(actionSet)
	{
		var html = '';

		var actionTableContent = $('#action-table-content');
		actionTableContent.html('');

		for (var actionIndex=0; actionIndex<actionSet.length; actionIndex++) {

			var action = actionSet[actionIndex];
			//console.log(action);
	  
			html += '<tr><td class="action-name">' + action.name + '</td><td class="action-arguments">';
	  

			//console.log(action);

			if( action.args !== null && action.args !== false )
			{
				var first = true;
				for( var argIndex=0; argIndex< action.args.length; argIndex++)
				{
					var arg = action.args[argIndex];
					if( argIndex != 0 )
						html += '<br>';
					first = false;
					var help =  (arg.help !== undefined) ? arg.help : 'description not available';
					
					html += '<span class="bs-tooltip" "data-toggle="tooltip" data-placement="top" title="'+help+'">#' + (argIndex+1) + ' ' +arg.name + '</span>'
				   
				}
			}
			html += '</td><td class="action-arg-type">';

			if( action.args !== null && action.args !== false )
			{
				var first = true;
				for( var argIndex=0; argIndex< action.args.length; argIndex++)
				{
					var arg = action.args[argIndex];
					if( argIndex != 0 )
						html += '<br>';
					first = false;
					html += arg.type;
				}
			}
			html += '</td><td class="action-default-value">';

			if( action.args !== null && action.args !== false )
			{
				var first = true;
				for( var argIndex=0; argIndex< action.args.length; argIndex++)
				{
					var arg = action.args[argIndex];
					if( argIndex != 0 )
						html += '<br>';
					first = false;
					html += arg.default;
				}
			}
			html += '</td><td class="action-choices">';

			if( action.args !== null && action.args !== false )
			{
				var first = true;
				for( var argIndex=0; argIndex< action.args.length; argIndex++)
				{
					var arg = action.args[argIndex];
					if( argIndex != 0 )
						html += '<br>';
					first = false;

					if( arg.choices !== undefined )
					{
						var firstArg = true;
						for( var choice of arg.choices ) {
							if( !firstArg )
								html += ' | ';
							html += choice;
							firstArg = false;
						}
					}
					else{
						html += '&nbsp';
					}
				}
			}
			html += '</td><td class="action-help">';
	
			if( action.help !== null ) {
				//Remove &nbsp;
				var re = new RegExp('&nbsp', 'g');
				var helpString = action.help.replace(re," ");
				var help = helpString;
				//@todo calcule ratio largeur fenetre td
				var  helpMaxSize = 150;

				if(help.length > helpMaxSize) {
					 help =  '<div class="expander">' + truncateHTML(helpString, helpMaxSize);
					 help += '...</div>';
					 help += '<div style="display:none" class="content">'+helpString+'</div>'
				}
				html += help;
			}
			
			html += '</td>';





			html += '</tr>';
		}

		actionTableContent.html(html);
		$('.bs-tooltip').tooltip();
		
		$('.expander').off('click').on('click',function() {
			var html = $(this).html()

			$(this).html($(this).next().html());
			$(this).next().html(html);
		});
	}
	
	function displayActionWindow()
	{
		//Update table
		$('#actions-select').on('change', function() {
			var value = this.value;
			updateActionTable(data.actions[value]);
		});
		//Default
		updateActionTable(data.actions.rule);
	
		//Selectbox
		var theHtml = '';
		for (var key in data.actions) {
			theHtml += '<option value="'+key+'">' + key + '</option>';
		}
		$('#actions-select').html(theHtml);
	}