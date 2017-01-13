function updateFilterTable(filterSet)
	{
		var html = '';

		var filterTableContent = $('#filter-table-content');
		filterTableContent.html('');

		for (var filterIndex=0; filterIndex<filterSet.length; filterIndex++) {

			var filter = filterSet[filterIndex];
			//console.log(filter);
	  
			html += '<tr><td class="filter-name">' + filter.name + '</td><td class="filter-arguments">';
	  
			//OPERATORS
			if(filter.operators.length > 0) {
				html+= '<table class="table table-striped">';
				html+= '<tbody>';
				for(var idx = 0; idx < filter.operators.length; idx++) {
					html+= '<tr>';
					
					for (var key in filter.operators[idx]) {
						var width = 25;
						if('name' == key) {
							width=75;
						}
						html+= '<td style="width:'+width+'%;">'+filter.operators[idx][key] +' </td>';
					}
					html+='</tr>';
				}
				html+= '</tbody></table>';
			}
			//console.log(filter.operators.length);
			html += '</td><td class="filter-help">';
			if( filter.help !== null ) {
				//Remove &nbsp;
				var re = new RegExp('&nbsp', 'g');
				var helpString = filter.help.replace(re," ");
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

		filterTableContent.html(html);
		$('.bs-tooltip').tooltip();
		
		$('.expander').off('click').on('click',function() {
			var html = $(this).html()

			$(this).html($(this).next().html());
			$(this).next().html(html);
		});
	}
	
	function displayFilterWindow()
	{
		$('#filters-select').on('change', function() {
			var value = this.value;
			updateFilterTable(data.filters[value]);
		});
		
		//Default
		updateFilterTable(data.filters.rule);
		
		//Selectbox
		var theHtml = '';
		for (var key in data.filters) {
			theHtml += '<option value="'+key+'">' + key + '</option>';
		}
		$('#filters-select').html(theHtml);
	
		
	}