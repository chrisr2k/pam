(function($) {
    'use strict';

    function toggleProviderFields() {
        var provider = $('#id_provider').val();

        // Show/hide AWS fields
        $('.aws-fields').toggle(provider === 'AWS');
        $('.entra-fields').toggle(provider === 'ENTRA');

        // Also toggle individual field rows by data attribute
        $('[data-provider-field]').each(function() {
            var $row = $(this).closest('.form-row');
            if ($row.length) {
                $row.toggle($(this).data('provider-field') === provider);
            }
        });
    }

    $(document).ready(function() {
        // Initial toggle
        toggleProviderFields();

        // Toggle on change
        $('#id_provider').on('change', toggleProviderFields);
    });

})(django.jQuery);
